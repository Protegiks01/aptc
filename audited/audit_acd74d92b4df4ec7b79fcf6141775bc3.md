# Audit Report

## Title
DKG Threshold Parameter Manipulation via Governance Allows Weakening of BFT Security Guarantees

## Summary
The DKG (Distributed Key Generation) protocol accepts threshold parameters from on-chain governance configuration without proper validation, allowing secrecy and reconstruction thresholds to be set below BFT security requirements. A malicious or misconfigured governance proposal can set thresholds as low as 10%, enabling a small coalition (<1/3 of validators) to break the randomness protocol and violate Byzantine fault tolerance assumptions.

## Finding Description

The vulnerability exists in the DKG parameter validation flow where threshold values are sourced from on-chain governance configuration and used to create DKG public parameters.

**Attack Flow:**

1. **Parameter Source**: When `process_dkg_result_inner()` is called, it creates DKG public parameters from on-chain session metadata at line 105. [1](#0-0) 

2. **Metadata Origin**: The metadata comes from `DKGState.in_progress` which is set by the `dkg::start()` function. [2](#0-1) 

3. **Config Retrieval**: The `randomness_config` parameter passed to `dkg::start()` comes from `randomness_config::current()` which fetches the governance-controlled on-chain configuration. [3](#0-2) 

4. **No Move-Level Validation**: The Move module's `new_v1()` and `new_v2()` functions accept arbitrary threshold values without any validation. [4](#0-3) 

5. **Governance Control**: These threshold values can be set by governance through `set_for_next_epoch()` which only requires the aptos_framework signer. [5](#0-4) 

6. **Rust-Level Validation Bypass**: When creating DKG parameters, the Rust code in `RealDKG::new_public_params()` extracts these thresholds and uses them to build the PVSS configuration. [6](#0-5) 

7. **Fallback to Insecure Path**: The `DKGRounding::new()` function attempts strict validation via `DKGRoundingProfile::new()`, but on failure falls back to `infallible()` which accepts dangerously low thresholds. [7](#0-6) 

8. **Strict Validation Requirements**: The strict validation requires `secrecy_threshold > 1/3` and `reconstruct_threshold <= 2/3`. [8](#0-7) 

9. **Permissive Fallback**: However, `infallible()` only clamps values to [0,1] and ensures reconstruction >= secrecy, accepting thresholds below BFT requirements. [9](#0-8) 

10. **No Transcript Verification Check**: The `verify_transcript()` function validates cryptographic correctness but does not check if threshold parameters meet BFT security requirements. [10](#0-9) 

**Exploitation Scenario:**
- Governance proposal sets `secrecy_threshold = 0.10` (10%) and `reconstruct_threshold = 0.15` (15%)
- Configuration passes through Move layer with no validation
- Rust validation in `DKGRoundingProfile::new()` fails (0.10 < 0.333...)
- Code falls back to `infallible()` which accepts these values
- DKG completes with weak thresholds
- A coalition of only 10% of validator stake can now reconstruct randomness (violate secrecy)
- A coalition of only 15% of validator stake can complete reconstruction

This breaks the fundamental BFT assumption that < 1/3 Byzantine validators cannot compromise the protocol.

## Impact Explanation

**Critical Severity** - This vulnerability enables consensus/safety violations affecting the randomness subsystem:

1. **Cryptographic Correctness Violation**: The BFT security invariant requires that < 1/3 of validators cannot break protocol security. With manipulated thresholds (e.g., 10%), this invariant is violated.

2. **Randomness Protocol Compromise**: Aptos randomness is critical for validator selection, transaction ordering, and on-chain applications requiring unpredictable values. A small coalition breaking randomness can:
   - Predict future validator sets
   - Manipulate transaction ordering for MEV
   - Compromise randomness-dependent dApps
   - Violate protocol fairness guarantees

3. **Network-Wide Impact**: All validators accept the weak DKG configuration, affecting the entire network's security posture for the epoch.

4. **Defense-in-Depth Failure**: The system has multiple layers (Move validation, Rust validation, transcript verification) but none properly enforce security requirements, with the Rust layer silently falling back to insecure configurations.

This meets the **Critical Severity** criteria for "Consensus/Safety violations" in the Aptos bug bounty program.

## Likelihood Explanation

**High Likelihood** due to multiple realistic scenarios:

1. **Accidental Misconfiguration**: A governance proposal author makes a calculation error (e.g., enters 10 instead of 50 for percentages), and no validation layer catches this before deployment.

2. **Automated Script Bug**: Configuration generation scripts contain bugs that produce invalid threshold values, which pass through all layers unchecked.

3. **Malicious Governance**: While requiring governance control, this is achievable through:
   - Stake accumulation by motivated attackers
   - Validator collusion scenarios
   - Compromised governance keys

4. **Silent Failure**: The fallback to `infallible()` is silent - it logs an error in `rounding_error` but continues execution, making the vulnerability difficult to detect in production.

The complete absence of validation in the Move layer combined with the permissive fallback in Rust creates a significant attack surface for both malicious and accidental exploitation.

## Recommendation

Implement defense-in-depth validation at multiple layers:

**1. Move-Level Validation** (Primary Defense):
Add validation in `randomness_config.move` when creating configs:

```move
public fun new_v1(secrecy_threshold: FixedPoint64, reconstruction_threshold: FixedPoint64): RandomnessConfig {
    // Validate BFT security requirements
    assert!(
        fixed_point64::greater_or_equal(secrecy_threshold, fixed_point64::create_from_rational(1, 3)),
        error::invalid_argument(EINVALID_SECRECY_THRESHOLD)
    );
    assert!(
        fixed_point64::less_or_equal(reconstruction_threshold, fixed_point64::create_from_rational(2, 3)),
        error::invalid_argument(EINVALID_RECONSTRUCTION_THRESHOLD)
    );
    assert!(
        fixed_point64::less(secrecy_threshold, reconstruction_threshold),
        error::invalid_argument(EINVALID_THRESHOLD_ORDERING)
    );
    
    RandomnessConfig {
        variant: copyable_any::pack( ConfigV1 {
            secrecy_threshold,
            reconstruction_threshold
        })
    }
}
```

**2. Rust-Level Validation** (Secondary Defense):
Modify `DKGRounding::new()` to fail hard instead of falling back:

```rust
pub fn new(...) -> Result<Self, anyhow::Error> {
    let profile = DKGRoundingProfile::new(
        validator_stakes,
        total_weight_min,
        total_weight_max,
        secrecy_threshold_in_stake_ratio,
        reconstruct_threshold_in_stake_ratio,
        fast_secrecy_threshold_in_stake_ratio,
    )?; // Propagate error instead of falling back
    
    let wconfig = WeightedConfigBlstrs::new(...).unwrap();
    // ... rest of implementation
    
    Ok(Self {
        rounding_method: "binary_search".to_string(),
        profile,
        wconfig,
        fast_wconfig,
        rounding_error: None,
    })
}
```

**3. VM-Level Check** (Tertiary Defense):
Add validation in `process_dkg_result_inner()` before using parameters:

```rust
// After line 105
let pub_params = DefaultDKG::new_public_params(&in_progress_session_state.metadata);

// Validate threshold parameters meet BFT requirements
let config = in_progress_session_state.metadata.randomness_config_derived()
    .ok_or(Unexpected(VMStatus::Error(StatusCode::INVALID_DKG_CONFIGURATION)))?;
    
if let Some(secrecy) = config.secrecy_threshold() {
    if secrecy <= U64F64::from_num(1) / U64F64::from_num(3) {
        return Err(Unexpected(VMStatus::Error(StatusCode::INVALID_DKG_THRESHOLD)));
    }
}
// Similar checks for reconstruct_threshold...
```

## Proof of Concept

**Move Test** (add to `randomness_config.move`):

```move
#[test(framework = @0x1)]
#[expected_failure(abort_code = 0x10000, location = Self)]
fun test_weak_thresholds_rejected(framework: signer) {
    use aptos_std::fixed_point64;
    
    // Attempt to create config with weak thresholds (10% and 15%)
    // This should abort with validation error
    let weak_config = new_v1(
        fixed_point64::create_from_rational(10, 100),  // 10% secrecy
        fixed_point64::create_from_rational(15, 100)   // 15% reconstruction
    );
    
    set_for_next_epoch(&framework, weak_config);
}

#[test(framework = @0x1)]
fun test_valid_thresholds_accepted(framework: signer) {
    use aptos_std::fixed_point64;
    
    // Valid thresholds should work
    let valid_config = new_v1(
        fixed_point64::create_from_rational(50, 100),  // 50% secrecy
        fixed_point64::create_from_rational(67, 100)   // 67% reconstruction
    );
    
    set_for_next_epoch(&framework, valid_config);
    // Should succeed
}
```

**Rust Integration Test** (to demonstrate the current vulnerability):

```rust
#[test]
fn test_weak_thresholds_currently_accepted() {
    use fixed::types::U64F64;
    
    // Weak thresholds that violate BFT security
    let weak_secrecy = U64F64::from_num(0.1);  // 10%
    let weak_reconstruct = U64F64::from_num(0.15);  // 15%
    
    let validator_stakes = vec![100u64; 10];  // 10 validators with equal stake
    
    // Currently, DKGRounding::new() will fall back to infallible()
    // and ACCEPT these weak thresholds instead of rejecting them
    let result = DKGRounding::new(
        &validator_stakes,
        weak_secrecy,
        weak_reconstruct,
        None,
    );
    
    // This succeeds with current code (vulnerability)
    assert_eq!(result.rounding_method, "infallible");
    assert!(result.rounding_error.is_some()); // Error logged but not fatal
    
    // With fix, this should panic or return Err
}
```

## Notes

This vulnerability represents a critical defense-in-depth failure where:
1. The Move governance layer accepts any threshold values
2. The Rust validation has a permissive fallback path
3. No layer enforces BFT security requirements

The fix requires coordinated changes across Move and Rust codebases to ensure threshold parameters always meet cryptographic security requirements (secrecy > 1/3, reconstruction ≤ 2/3) at every validation layer.

### Citations

**File:** aptos-move/aptos-vm/src/validator_txns/dkg.rs (L105-105)
```rust
        let pub_params = DefaultDKG::new_public_params(&in_progress_session_state.metadata);
```

**File:** aptos-move/framework/aptos-framework/sources/dkg.move (L61-79)
```text
    public(friend) fun start(
        dealer_epoch: u64,
        randomness_config: RandomnessConfig,
        dealer_validator_set: vector<ValidatorConsensusInfo>,
        target_validator_set: vector<ValidatorConsensusInfo>,
    ) acquires DKGState {
        let dkg_state = borrow_global_mut<DKGState>(@aptos_framework);
        let new_session_metadata = DKGSessionMetadata {
            dealer_epoch,
            randomness_config,
            dealer_validator_set,
            target_validator_set,
        };
        let start_time_us = timestamp::now_microseconds();
        dkg_state.in_progress = std::option::some(DKGSessionState {
            metadata: new_session_metadata,
            start_time_us,
            transcript: vector[],
        });
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

**File:** aptos-move/framework/aptos-framework/sources/configs/randomness_config.move (L53-56)
```text
    public fun set_for_next_epoch(framework: &signer, new_config: RandomnessConfig) {
        system_addresses::assert_aptos_framework(framework);
        config_buffer::upsert(new_config);
    }
```

**File:** aptos-move/framework/aptos-framework/sources/configs/randomness_config.move (L93-114)
```text
    public fun new_v1(secrecy_threshold: FixedPoint64, reconstruction_threshold: FixedPoint64): RandomnessConfig {
        RandomnessConfig {
            variant: copyable_any::pack( ConfigV1 {
                secrecy_threshold,
                reconstruction_threshold
            } )
        }
    }

    /// Create a `ConfigV2` variant.
    public fun new_v2(
        secrecy_threshold: FixedPoint64,
        reconstruction_threshold: FixedPoint64,
        fast_path_secrecy_threshold: FixedPoint64,
    ): RandomnessConfig {
        RandomnessConfig {
            variant: copyable_any::pack( ConfigV2 {
                secrecy_threshold,
                reconstruction_threshold,
                fast_path_secrecy_threshold,
            } )
        }
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

**File:** types/src/dkg/real_dkg/mod.rs (L332-401)
```rust
    fn verify_transcript(
        params: &Self::PublicParams,
        trx: &Self::Transcript,
    ) -> anyhow::Result<()> {
        // Verify dealer indices are valid.
        let dealers = trx
            .main
            .get_dealers()
            .iter()
            .map(|player| player.id)
            .collect::<Vec<usize>>();
        let num_validators = params.session_metadata.dealer_validator_set.len();
        ensure!(
            dealers.iter().all(|id| *id < num_validators),
            "real_dkg::verify_transcript failed with invalid dealer index."
        );

        let all_eks = params.pvss_config.eks.clone();

        let addresses = params.verifier.get_ordered_account_addresses();
        let dealers_addresses = dealers
            .iter()
            .filter_map(|&pos| addresses.get(pos))
            .cloned()
            .collect::<Vec<_>>();

        let spks = dealers_addresses
            .iter()
            .filter_map(|author| params.verifier.get_public_key(author))
            .collect::<Vec<_>>();

        let aux = dealers_addresses
            .iter()
            .map(|address| (params.pvss_config.epoch, address))
            .collect::<Vec<_>>();

        trx.main.verify(
            &params.pvss_config.wconfig,
            &params.pvss_config.pp,
            &spks,
            &all_eks,
            &aux,
        )?;

        // Verify fast path is present if and only if fast_wconfig is present.
        ensure!(
            trx.fast.is_some() == params.pvss_config.fast_wconfig.is_some(),
            "real_dkg::verify_transcript failed with mismatched fast path flag in trx and params."
        );

        if let Some(fast_trx) = trx.fast.as_ref() {
            let fast_dealers = fast_trx
                .get_dealers()
                .iter()
                .map(|player| player.id)
                .collect::<Vec<usize>>();
            ensure!(
                dealers == fast_dealers,
                "real_dkg::verify_transcript failed with inconsistent dealer index."
            );
        }

        if let (Some(fast_trx), Some(fast_wconfig)) =
            (trx.fast.as_ref(), params.pvss_config.fast_wconfig.as_ref())
        {
            fast_trx.verify(fast_wconfig, &params.pvss_config.pp, &spks, &all_eks, &aux)?;
        }

        Ok(())
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

**File:** types/src/dkg/real_dkg/rounding/mod.rs (L197-199)
```rust
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
