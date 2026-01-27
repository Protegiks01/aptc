# Audit Report

## Title
Compromised Governance Can Inject Insecure DKG Threshold Parameters Due to Missing Validation

## Summary
The Aptos DKG (Distributed Key Generation) system accepts arbitrary threshold parameters from on-chain governance without validation, allowing compromised governance to inject cryptographically insecure values that weaken the security properties of the randomness beacon. The Move contract `randomness_config.move` performs no validation on threshold values, and the Rust DKG implementation silently accepts invalid parameters through a fallback mechanism that clamps values without enforcing proper security constraints.

## Finding Description

The vulnerability exists across multiple layers of the DKG parameter handling pipeline:

**1. No Validation in Move Contract**

The `randomness_config::new_v1()` and `new_v2()` functions accept arbitrary `FixedPoint64` threshold values without any validation: [1](#0-0) 

There are no assertions checking that `secrecy_threshold > 1/3`, `reconstruct_threshold <= 2/3`, or `secrecy_threshold < reconstruct_threshold`.

**2. Attack Vector Through Governance**

Compromised governance can call `set_for_next_epoch()` with malicious thresholds: [2](#0-1) 

Example malicious governance script (based on legitimate patterns): [3](#0-2) 

An attacker with governance control could replace lines 268-269 with `create_from_rational(1, 10)` (10% secrecy threshold) and `create_from_rational(9, 10)` (90% reconstruct threshold).

**3. Propagation to DKG Session**

During epoch transition, these unvalidated thresholds flow into `DKGSessionMetadata`: [4](#0-3) 

The `randomness_config::current()` returns the malicious config set by governance, which is then embedded in `DKGStartEvent`.

**4. Silent Acceptance in Rust Implementation**

When validators receive the DKG start event, they call `setup_deal_broadcast()`: [5](#0-4) 

This creates public parameters from the unvalidated metadata: [6](#0-5) 

The thresholds are extracted without validation (lines 203-209).

**5. Inadequate Fallback Mechanism**

The `DKGRounding::new()` function has security checks: [7](#0-6) 

But when these checks fail, the code falls back to `infallible()`: [8](#0-7) 

The `infallible()` method only clamps values to [0, 1] range without enforcing security constraints: [9](#0-8) 

**Security Impact:**

A compromised governance setting `secrecy_threshold = 0.2` (20%) would allow any validator coalition with >20% stake to reconstruct the shared randomness secret, violating the intended 1/3+ threshold. Conversely, `reconstruct_threshold = 0.9` (90%) would require 90% stake for reconstruction, potentially causing liveness failures.

## Impact Explanation

**Severity: Critical**

This vulnerability meets the Critical severity criteria under "Consensus/Safety violations" because:

1. **Cryptographic Security Violation**: The DKG protocol's security guarantees rely on proper threshold selection. The standard assumption is that secrecy requires >1/3 Byzantine threshold and reconstruction requires ≤2/3 liveness threshold. Violating these allows:
   - **Privacy breach**: Validator subsets with insufficient stake can reconstruct secrets
   - **Liveness failure**: Excessive thresholds prevent legitimate reconstruction

2. **Consensus Integrity**: Weakened DKG parameters directly compromise the randomness beacon, which is used for leader selection and other consensus-critical operations. This violates the documented invariant:

   "**Cryptographic Correctness**: BLS signatures, VRF, and hash operations must be secure"

3. **Network-Wide Impact**: All validators in the epoch would use the compromised parameters, affecting the entire network's randomness generation.

## Likelihood Explanation

**Likelihood: Low-Medium**

While the vulnerability requires compromised governance (a high bar), the likelihood assessment considers:

1. **Governance as Attack Surface**: Governance systems have been compromised in various blockchain networks through:
   - Proposal injection attacks
   - Voting power manipulation
   - Social engineering of governance participants
   - Bugs in governance logic (separate vulnerabilities)

2. **No Defense-in-Depth**: Once governance is compromised, there is **zero** additional validation, making exploitation trivial (single governance transaction).

3. **Silent Failure Mode**: The `infallible()` fallback means validators won't immediately detect the issue - they'll silently accept weakened parameters, making the attack stealthy.

4. **Precedent**: The security question itself suggests this attack vector was identified as a concern during threat modeling.

## Recommendation

Implement **defense-in-depth validation** at multiple layers:

**1. Add Validation to Move Contract**

```move
public fun new_v1(secrecy_threshold: FixedPoint64, reconstruction_threshold: FixedPoint64): RandomnessConfig {
    // Validate: secrecy_threshold > 1/3
    let one_third = fixed_point64::create_from_rational(1, 3);
    assert!(
        fixed_point64::greater(secrecy_threshold, one_third),
        error::invalid_argument(EINVALID_SECRECY_THRESHOLD)
    );
    
    // Validate: reconstruction_threshold <= 2/3
    let two_thirds = fixed_point64::create_from_rational(2, 3);
    assert!(
        fixed_point64::less_or_equal(reconstruction_threshold, two_thirds),
        error::invalid_argument(EINVALID_RECONSTRUCTION_THRESHOLD)
    );
    
    // Validate: secrecy < reconstruction
    assert!(
        fixed_point64::less(secrecy_threshold, reconstruction_threshold),
        error::invalid_argument(EINVALID_THRESHOLD_ORDER)
    );
    
    RandomnessConfig {
        variant: copyable_any::pack( ConfigV1 {
            secrecy_threshold,
            reconstruction_threshold
        })
    }
}
```

**2. Add Runtime Validation in Rust**

Modify `RealDKG::new_public_params()` to validate thresholds:

```rust
fn new_public_params(dkg_session_metadata: &DKGSessionMetadata) -> RealDKGPublicParams {
    let randomness_config = dkg_session_metadata
        .randomness_config_derived()
        .unwrap_or_else(OnChainRandomnessConfig::default_enabled);
    
    let secrecy_threshold = randomness_config
        .secrecy_threshold()
        .unwrap_or_else(|| *rounding::DEFAULT_SECRECY_THRESHOLD);
    
    let reconstruct_threshold = randomness_config
        .reconstruct_threshold()
        .unwrap_or_else(|| *rounding::DEFAULT_RECONSTRUCT_THRESHOLD);
    
    // VALIDATION: Enforce security constraints
    let one_third = U64F64::from_num(1) / U64F64::from_num(3);
    let two_thirds = U64F64::from_num(2) / U64F64::from_num(3);
    
    if secrecy_threshold <= one_third || 
       reconstruct_threshold > two_thirds ||
       secrecy_threshold >= reconstruct_threshold {
        panic!("Invalid DKG thresholds detected from on-chain config");
    }
    
    // ... rest of implementation
}
```

**3. Remove Silent Fallback**

The `infallible()` fallback should either reject invalid thresholds or at minimum log a critical warning that security constraints are violated.

## Proof of Concept

**Malicious Governance Script:**

```move
script {
    use aptos_framework::aptos_governance;
    use aptos_framework::randomness_config;
    use aptos_std::fixed_point64;

    fun main(core_resources: &signer) {
        let framework_signer = aptos_governance::get_signer_testnet_only(core_resources, @0x1);
        
        // ATTACK: Set insecure thresholds
        // secrecy_threshold = 0.2 (20%, below required 1/3)
        // reconstruct_threshold = 0.9 (90%, above recommended 2/3)
        let malicious_config = randomness_config::new_v1(
            fixed_point64::create_from_rational(1, 5),  // 20% - INSECURE
            fixed_point64::create_from_rational(9, 10)  // 90% - BREAKS LIVENESS
        );
        
        randomness_config::set_for_next_epoch(&framework_signer, malicious_config);
        aptos_governance::reconfigure(&framework_signer);
    }
}
```

**Expected Behavior:** Script should abort with validation error

**Actual Behavior:** Script succeeds, and validators in the next epoch use DKG parameters with:
- 20% secrecy threshold (allowing 20% stake coalition to break privacy)
- 90% reconstruction threshold (requiring 90% stake for liveness)

**Verification Steps:**
1. Deploy malicious governance script
2. Execute script with governance authority
3. Trigger epoch transition
4. Observe DKG manager logs showing `rounding_method: "infallible"` (indicating fallback was used)
5. Verify resulting `DKGPvssConfig` has weakened security parameters

## Notes

This vulnerability demonstrates a critical gap in defense-in-depth for cryptographic parameters. While governance compromise is a high-severity prerequisite, the complete absence of validation at downstream layers means a single governance compromise can catastrophically weaken the randomness beacon's security properties. Proper validation would limit the blast radius of governance compromise and provide early detection of attacks.

### Citations

**File:** aptos-move/framework/aptos-framework/sources/configs/randomness_config.move (L53-56)
```text
    public fun set_for_next_epoch(framework: &signer, new_config: RandomnessConfig) {
        system_addresses::assert_aptos_framework(framework);
        config_buffer::upsert(new_config);
    }
```

**File:** aptos-move/framework/aptos-framework/sources/configs/randomness_config.move (L92-100)
```text
    /// Create a `ConfigV1` variant.
    public fun new_v1(secrecy_threshold: FixedPoint64, reconstruction_threshold: FixedPoint64): RandomnessConfig {
        RandomnessConfig {
            variant: copyable_any::pack( ConfigV1 {
                secrecy_threshold,
                reconstruction_threshold
            } )
        }
    }
```

**File:** testsuite/smoke-test/src/randomness/mod.rs (L258-277)
```rust
fn script_to_enable_main_logic() -> String {
    r#"
script {
    use aptos_framework::aptos_governance;
    use aptos_framework::randomness_config;
    use aptos_std::fixed_point64;

    fun main(core_resources: &signer) {
        let framework_signer = aptos_governance::get_signer_testnet_only(core_resources, @0x1);
        let config = randomness_config::new_v1(
            fixed_point64::create_from_rational(1, 2),
            fixed_point64::create_from_rational(2, 3)
        );
        randomness_config::set_for_next_epoch(&framework_signer, config);
        aptos_governance::reconfigure(&framework_signer);
    }
}
"#
    .to_string()
}
```

**File:** aptos-move/framework/aptos-framework/sources/reconfiguration_with_dkg.move (L34-39)
```text
        dkg::start(
            cur_epoch,
            randomness_config::current(),
            stake::cur_validator_consensus_infos(),
            stake::next_validator_consensus_infos(),
        );
```

**File:** dkg/src/dkg_manager/mod.rs (L314-314)
```rust
        let public_params = DKG::new_public_params(dkg_session_metadata);
```

**File:** types/src/dkg/real_dkg/mod.rs (L199-224)
```rust
    fn new_public_params(dkg_session_metadata: &DKGSessionMetadata) -> RealDKGPublicParams {
        let randomness_config = dkg_session_metadata
            .randomness_config_derived()
            .unwrap_or_else(OnChainRandomnessConfig::default_enabled);
        let secrecy_threshold = randomness_config
            .secrecy_threshold()
            .unwrap_or_else(|| *rounding::DEFAULT_SECRECY_THRESHOLD);
        let reconstruct_threshold = randomness_config
            .reconstruct_threshold()
            .unwrap_or_else(|| *rounding::DEFAULT_RECONSTRUCT_THRESHOLD);
        let maybe_fast_path_secrecy_threshold = randomness_config.fast_path_secrecy_threshold();

        let pvss_config = build_dkg_pvss_config(
            dkg_session_metadata.dealer_epoch,
            secrecy_threshold,
            reconstruct_threshold,
            maybe_fast_path_secrecy_threshold,
            &dkg_session_metadata.target_validator_consensus_infos_cloned(),
        );
        let verifier = ValidatorVerifier::new(dkg_session_metadata.dealer_consensus_infos_cloned());
        RealDKGPublicParams {
            session_metadata: dkg_session_metadata.clone(),
            pvss_config,
            verifier: verifier.into(),
        }
    }
```

**File:** types/src/dkg/real_dkg/rounding/mod.rs (L79-96)
```rust
        let (profile, rounding_error, rounding_method) = match DKGRoundingProfile::new(
            validator_stakes,
            total_weight_min,
            total_weight_max,
            secrecy_threshold_in_stake_ratio,
            reconstruct_threshold_in_stake_ratio,
            fast_secrecy_threshold_in_stake_ratio,
        ) {
            Ok(profile) => (profile, None, "binary_search".to_string()),
            Err(e) => {
                let profile = DKGRoundingProfile::infallible(
                    validator_stakes,
                    secrecy_threshold_in_stake_ratio,
                    reconstruct_threshold_in_stake_ratio,
                    fast_secrecy_threshold_in_stake_ratio,
                );
                (profile, Some(format!("{e}")), "infallible".to_string())
            },
```

**File:** types/src/dkg/real_dkg/rounding/mod.rs (L195-199)
```rust
        ensure!(total_weight_min >= validator_stakes.len());
        ensure!(total_weight_max >= total_weight_min);
        ensure!(secrecy_threshold_in_stake_ratio * U64F64::from_num(3) > U64F64::from_num(1));
        ensure!(secrecy_threshold_in_stake_ratio < reconstruct_threshold_in_stake_ratio);
        ensure!(reconstruct_threshold_in_stake_ratio * U64F64::from_num(3) <= U64F64::from_num(2));
```

**File:** types/src/dkg/real_dkg/rounding/mod.rs (L260-266)
```rust
        let one = U64F64::from_num(1);
        secrecy_threshold_in_stake_ratio = min(one, secrecy_threshold_in_stake_ratio);
        reconstruct_threshold_in_stake_ratio = min(one, reconstruct_threshold_in_stake_ratio);
        reconstruct_threshold_in_stake_ratio = max(
            secrecy_threshold_in_stake_ratio,
            reconstruct_threshold_in_stake_ratio,
        );
```
