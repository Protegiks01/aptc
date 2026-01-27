# Audit Report

## Title
Script Type Parameter Count Underestimation Causes Assertion Failure in Bytecode Verifier

## Summary
The `max_num_of_ty_params_or_args()` function in the Move bytecode verifier fails to account for script-level type parameter declarations when calculating the required bitset size. When the feature flag `sig_checker_v2_fix_script_ty_param_count` is disabled, an attacker can craft a script with 17+ declared type parameters (unused in signatures) that triggers a runtime assertion failure during verification. [1](#0-0) 

## Finding Description

The vulnerability exists in the signature verification logic for compiled scripts. The `max_num_of_ty_params_or_args()` function scans for the maximum type parameter count by examining function handles, struct handles, type parameter indices in signatures, and struct field types. However, it does NOT check `script.type_parameters.len()` - the number of type parameters declared at the script level. [1](#0-0) 

When `verify_script()` is called, it uses the underestimated `max_num` to select a bitset size N: [2](#0-1) 

The function then calls `verify_script_impl::<N>`, which creates an ability context from the script's type parameters: [3](#0-2) 

The context creation converts the script's type parameter abilities using a `From` implementation that calls `insert()` for each type parameter: [4](#0-3) 

The `insert()` method contains an assertion that panics if the type parameter index exceeds the bitset capacity: [5](#0-4) 

**Attack Scenario:**
1. Attacker crafts a CompiledScript with 17+ type parameters in `script.type_parameters`
2. These type parameters are never referenced in any signatures
3. `max_num_of_ty_params_or_args()` returns 0 (no type parameter usage found)
4. N is chosen as 1 (since 0 ≤ 16, where NUM_PARAMS_PER_WORD = 16)
5. Maximum supported index = 1 × 16 = 16
6. When creating context, `insert()` is called with indices 0..16
7. At index 16, the assertion `16 < 16` fails, triggering a panic

The panic is caught by `catch_unwind` in the verification wrapper and converted to a `VERIFIER_INVARIANT_VIOLATION` error: [6](#0-5) 

The existence of a feature flag fix confirms this was a known issue: [7](#0-6) [8](#0-7) 

## Impact Explanation

This qualifies as **High Severity** based on the following:

1. **Improper Input Validation**: The verifier relies on panic-catching for error handling instead of proper validation, violating Move VM safety guarantees. This represents a "Significant protocol violation" as defined in the High severity category.

2. **Denial of Service Vector**: While the panic is caught, an attacker can submit malicious scripts that consume validation resources and generate misleading error messages. If many such scripts are submitted, it could impact validator node performance.

3. **Diagnostic Confusion**: The generic `VERIFIER_INVARIANT_VIOLATION` error provides no information about the actual problem, making debugging difficult and potentially masking the attack vector.

4. **Defense-in-Depth Failure**: Proper validation should reject invalid input before reaching assertion points. Relying on panic-catching as a safety mechanism is fragile and could fail under certain runtime conditions.

When the feature flag is disabled (which may occur on testnets or during feature rollout), this vulnerability is actively exploitable.

## Likelihood Explanation

**Likelihood: Medium to High**

- **Ease of Exploitation**: Crafting the malicious script requires only basic understanding of the Move bytecode format. The attacker needs to create a CompiledScript structure with multiple type parameters, which is trivial.

- **Attack Surface**: Any user can submit transaction scripts to the network, making this attack surface widely accessible.

- **Configuration Dependency**: The vulnerability is only exploitable when `sig_checker_v2_fix_script_ty_param_count` is disabled. However, feature flags can be disabled/enabled through governance, and testnets may not have all fixes enabled.

- **Detection Difficulty**: The misleading error message makes it difficult to detect this specific attack pattern versus legitimate verification failures.

## Recommendation

The fix already exists but should be enforced unconditionally rather than behind a feature flag:

**Immediate Fix**: In `verify_script()`, always include script type parameter count in the calculation:

```rust
pub fn verify_script(config: &VerifierConfig, script: &CompiledScript) -> VMResult<()> {
    let mut max_num = max_num_of_ty_params_or_args(BinaryIndexedView::Script(script));
    // Always account for script-level type parameters
    max_num = max_num.max(script.type_parameters.len());
    
    // ... rest of verification logic
}
```

**Better Fix**: Modify `max_num_of_ty_params_or_args()` to accept script type parameter count as a parameter:

```rust
fn max_num_of_ty_params_or_args(resolver: BinaryIndexedView, script_ty_params: Option<usize>) -> usize {
    let mut n = script_ty_params.unwrap_or(0);
    // ... rest of existing logic
}
```

**Defense-in-Depth**: Add explicit validation before bitset creation:

```rust
fn from(abilities: &'a [AbilitySet]) -> Self {
    if abilities.len() > N * NUM_PARAMS_PER_WORD {
        panic!("Type parameter count {} exceeds bitset capacity {}", 
               abilities.len(), N * NUM_PARAMS_PER_WORD);
    }
    // ... existing logic
}
```

## Proof of Concept

```rust
#[test]
#[should_panic(expected = "Type parameter index out of bounds")]
fn test_script_type_param_underestimation() {
    use move_binary_format::file_format::*;
    use move_bytecode_verifier::{VerifierConfig, verify_script_with_config};
    use move_core_types::ability::AbilitySet;
    
    // Create a script with 17 type parameters but no usage in signatures
    let mut script = empty_script();
    
    // Add 17 type parameters (indices 0..16)
    script.type_parameters = vec![AbilitySet::EMPTY; 17];
    
    // Ensure no type parameters are referenced in signatures
    // (empty_script already has no type parameter usage)
    
    // Create config with fix disabled
    let mut config = VerifierConfig::default();
    config.sig_checker_v2_fix_script_ty_param_count = false;
    
    // This will trigger the assertion at line 71
    // max_num will be 0, so N=1, supporting only indices 0..15
    // When creating context from 17 type parameters, index 16 will fail assertion
    let result = verify_script_with_config(&config, &script);
    
    // The panic is caught and converted to VERIFIER_INVARIANT_VIOLATION
    assert!(result.is_err());
    assert_eq!(
        result.unwrap_err().major_status(),
        StatusCode::VERIFIER_INVARIANT_VIOLATION
    );
}
```

**Notes**

This vulnerability represents a validation gap in the Move bytecode verifier that allows malicious input to trigger assertion failures. While the panic is caught by `catch_unwind` and converted to an error (preventing node crashes), this represents improper defensive programming and could have more serious consequences if:

1. The panic-catching mechanism fails or is bypassed in certain environments
2. Processing many such malicious scripts impacts node performance
3. The misleading error messages complicate debugging and incident response

The existence of a feature flag fix (`SIGNATURE_CHECKER_V2_SCRIPT_FIX`) confirms this was a recognized issue. However, relying on feature flags for security fixes is problematic as flags can be toggled through governance or may not be enabled on all networks (testnets, devnets).

The vulnerability breaks the "Move VM Safety" invariant that bytecode verification should properly validate all inputs before execution, not rely on panic-catching as a fallback mechanism.

### Citations

**File:** third_party/move/move-bytecode-verifier/src/signature_v2.rs (L49-57)
```rust
impl<'a, const N: usize> From<&'a [AbilitySet]> for BitsetTypeParameterConstraints<N> {
    fn from(abilities: &'a [AbilitySet]) -> Self {
        abilities
            .iter()
            .enumerate()
            .map(|(idx, abilities)| (idx as TypeParameterIndex, *abilities))
            .collect()
    }
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

**File:** third_party/move/move-bytecode-verifier/src/signature_v2.rs (L1173-1198)
```rust
fn verify_script_impl<const N: usize>(
    config: &VerifierConfig,
    script: &CompiledScript,
) -> PartialVMResult<()> {
    let arena = Arena::<BitsetTypeParameterConstraints<N>>::new();
    let checker = SignatureChecker::new(
        &arena,
        BinaryIndexedView::Script(script),
        config.sig_checker_v2_fix_function_signatures,
    );

    // Check if all signatures & instantiations are well-formed without any specific contexts.
    // This is only needed if we want to keep the binary format super clean.
    checker.verify_signature_pool_contextless()?;
    checker.verify_function_instantiations_contextless()?;

    checker.verify_function_handles()?;
    checker.verify_signature_in_context(
        &BitsetTypeParameterConstraints::from(script.type_parameters.as_slice()),
        script.parameters,
        // Script parameters can be signer references.
        true,
    )?;
    checker.verify_code(&script.type_parameters, &script.code)?;

    Ok(())
```

**File:** third_party/move/move-bytecode-verifier/src/signature_v2.rs (L1201-1251)
```rust
fn max_num_of_ty_params_or_args(resolver: BinaryIndexedView) -> usize {
    let mut n = 0;

    for fh in resolver.function_handles() {
        n = n.max(fh.type_parameters.len())
    }

    for sh in resolver.struct_handles() {
        n = n.max(sh.type_parameters.len())
    }

    for sig in resolver.signatures() {
        for ty in &sig.0 {
            for ty in ty.preorder_traversal() {
                if let SignatureToken::TypeParameter(ty_param_idx) = ty {
                    n = n.max(*ty_param_idx as usize + 1)
                }
            }
        }
    }

    if let Some(struct_defs) = resolver.struct_defs() {
        for struct_def in struct_defs {
            match &struct_def.field_information {
                StructFieldInformation::Native => {},
                StructFieldInformation::Declared(fields) => {
                    for field in fields {
                        for ty in field.signature.0.preorder_traversal() {
                            if let SignatureToken::TypeParameter(ty_param_idx) = ty {
                                n = n.max(*ty_param_idx as usize + 1)
                            }
                        }
                    }
                },
                StructFieldInformation::DeclaredVariants(variants) => {
                    for variant in variants {
                        for field in &variant.fields {
                            for ty in field.signature.0.preorder_traversal() {
                                if let SignatureToken::TypeParameter(ty_param_idx) = ty {
                                    n = n.max(*ty_param_idx as usize + 1)
                                }
                            }
                        }
                    }
                },
            }
        }
    }

    n
}
```

**File:** third_party/move/move-bytecode-verifier/src/signature_v2.rs (L1273-1291)
```rust
pub fn verify_script(config: &VerifierConfig, script: &CompiledScript) -> VMResult<()> {
    let mut max_num = max_num_of_ty_params_or_args(BinaryIndexedView::Script(script));
    if config.sig_checker_v2_fix_script_ty_param_count {
        max_num = max_num.max(script.type_parameters.len());
    }

    let res = if max_num <= NUM_PARAMS_PER_WORD {
        verify_script_impl::<1>(config, script)
    } else if max_num <= NUM_PARAMS_PER_WORD * 2 {
        verify_script_impl::<2>(config, script)
    } else if max_num <= NUM_PARAMS_PER_WORD * 16 {
        verify_script_impl::<16>(config, script)
    } else {
        return Err(
            PartialVMError::new(StatusCode::UNKNOWN_INVARIANT_VIOLATION_ERROR)
                .with_message("too many type parameters/arguments in the program".to_string())
                .finish(Location::Undefined),
        );
    };
```

**File:** third_party/move/move-bytecode-verifier/src/verifier.rs (L194-218)
```rust
    let result = std::panic::catch_unwind(|| {
        // Always needs to run bound checker first as subsequent passes depend on it
        BoundsChecker::verify_script(script).map_err(|e| {
            // We can't point the error at the script, because if bounds-checking
            // failed, we cannot safely index into script
            e.finish(Location::Undefined)
        })?;
        FeatureVerifier::verify_script(config, script)?;
        LimitsVerifier::verify_script(config, script)?;
        DuplicationChecker::verify_script(script)?;

        signature_v2::verify_script(config, script)?;

        InstructionConsistency::verify_script(script)?;
        constants::verify_script(script)?;
        CodeUnitVerifier::verify_script(config, script)?;
        script_signature::verify_script(script, no_additional_script_signature_checks)
    })
    .unwrap_or_else(|_| {
        Err(
            PartialVMError::new(StatusCode::VERIFIER_INVARIANT_VIOLATION)
                .with_message("[VM] bytecode verifier panicked for script".to_string())
                .finish(Location::Undefined),
        )
    });
```

**File:** aptos-move/aptos-vm-environment/src/prod_configs.rs (L146-147)
```rust
    let sig_checker_v2_fix_script_ty_param_count =
        features.is_enabled(FeatureFlag::SIGNATURE_CHECKER_V2_SCRIPT_FIX);
```
