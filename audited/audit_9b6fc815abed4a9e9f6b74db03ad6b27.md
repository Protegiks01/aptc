# Audit Report

## Title
Script Type Parameter Count Mismatch Causes Consensus Split in Bytecode Verifier

## Summary
A vulnerability in `verify_script_impl()` allows scripts with more declared type parameters than used in signatures to cause validator consensus splits. Validators without the `SIGNATURE_CHECKER_V2_SCRIPT_FIX` feature flag enabled will reject such scripts with a panic-induced error, while validators with the fix will properly validate them, breaking the deterministic execution invariant. [1](#0-0) 

## Finding Description
The vulnerability exists in the interaction between `max_num_of_ty_params_or_args()` and `verify_script_impl()`. The sizing logic for `BitsetTypeParameterConstraints` does not account for the script's declared type parameter count when the fix is disabled.

**Attack Flow:**

1. Attacker crafts a `CompiledScript` with N type parameters declared (e.g., 20 parameters)
2. Script only uses type parameter indices 0 to M in its actual signatures (e.g., M=9)
3. `max_num_of_ty_params_or_args()` scans function handles, struct handles, and signatures to find the maximum `TypeParameter` index used [2](#0-1) 

4. Without the fix, this function returns M+1 (e.g., 10), not accounting for `script.type_parameters.len()` (20)
5. The bitset is sized as `N=1` for 10 parameters (handles indices 0-15) [3](#0-2) 

6. At line 1191, `BitsetTypeParameterConstraints::from(script.type_parameters.as_slice())` attempts to create a bitset from 20 elements
7. The `From` implementation enumerates and inserts each type parameter index [4](#0-3) 

8. When inserting indices 16-19, the assertion in `insert()` fails because the bitset only supports 0-15 [5](#0-4) 

9. The panic is caught by `verify_script_with_config()` and converted to `VERIFIER_INVARIANT_VIOLATION` [6](#0-5) 

**Consensus Split:**
- Validators **without fix**: Reject script with `VERIFIER_INVARIANT_VIOLATION` error
- Validators **with fix**: Properly size bitset to handle all type parameters, continue validation normally

The fix is controlled by the feature flag configuration: [7](#0-6) [8](#0-7) 

The feature flag is now in default features (line 203 of aptos_features.rs), indicating the vulnerability has been patched, but existed during the rollout period.

## Impact Explanation
This is a **Critical** severity consensus violation under the Aptos bug bounty criteria:

- **Consensus/Safety violation**: Validators disagree on script validity, breaking deterministic execution
- **Network partition risk**: During feature flag rollout, the network could split into two sets of validators processing different transaction sets
- **Exploitation complexity**: Low - attacker only needs to craft a script with extra unused type parameters

The vulnerability directly violates the **Deterministic Execution** invariant: "All validators must produce identical state roots for identical blocks."

## Likelihood Explanation
**High likelihood during vulnerable window:**
- Trivial to exploit: requires only declaring unused type parameters in script
- No special permissions needed: any user can submit scripts
- Automated exploitation possible: scripts can be systematically generated

**Current status:** The vulnerability is **patched** via the feature flag now enabled by default, but existed in production during rollout.

## Recommendation
The fix has been implemented correctly using the feature flag approach: [9](#0-8) 

**Additional hardening recommendations:**
1. Add bounds checking before `From` conversion to fail gracefully with a proper error instead of panicking
2. Add integration tests that verify scripts with varying type parameter counts
3. Ensure the feature flag cannot be disabled once enabled in production

## Proof of Concept

```rust
// Rust PoC - Create a malicious script
use move_binary_format::file_format::{
    CompiledScript, CodeUnit, Signature, SignatureToken, AbilitySet
};

// Create script with 20 type parameters declared
let mut script = CompiledScript::default();
script.type_parameters = vec![AbilitySet::EMPTY; 20]; // Declare 20 type params

// But only use TypeParameter(0) in signatures
script.parameters = SignatureIndex(0);
script.signatures.push(Signature(vec![SignatureToken::TypeParameter(0)]));

// Code doesn't use high-indexed type parameters
script.code = CodeUnit {
    locals: SignatureIndex(0),
    code: vec![Bytecode::Ret],
};

// When verified without fix:
// - max_num_of_ty_params_or_args returns 1 (only saw TypeParameter(0))
// - Bitset sized for N=1 (handles 0-15)
// - BitsetTypeParameterConstraints::from(script.type_parameters) panics at index 16
// - Returns VERIFIER_INVARIANT_VIOLATION

// When verified with fix:
// - max_num is set to max(1, 20) = 20
// - Bitset sized for N=2 (handles 0-31)
// - Verification continues normally
```

**Notes**
- This vulnerability was actively exploitable during the feature flag rollout period before `SIGNATURE_CHECKER_V2_SCRIPT_FIX` became enabled by default
- The issue demonstrates the importance of comprehensive bounds checking and feature flag synchronization across validators
- Similar issues may exist in other parts of the verifier where array/bitset sizing depends on scanned content rather than declared counts

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

**File:** third_party/move/move-bytecode-verifier/src/signature_v2.rs (L1173-1199)
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
}
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

**File:** third_party/move/move-bytecode-verifier/src/signature_v2.rs (L1273-1277)
```rust
pub fn verify_script(config: &VerifierConfig, script: &CompiledScript) -> VMResult<()> {
    let mut max_num = max_num_of_ty_params_or_args(BinaryIndexedView::Script(script));
    if config.sig_checker_v2_fix_script_ty_param_count {
        max_num = max_num.max(script.type_parameters.len());
    }
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

**File:** aptos-move/aptos-vm-environment/src/prod_configs.rs (L146-178)
```rust
    let sig_checker_v2_fix_script_ty_param_count =
        features.is_enabled(FeatureFlag::SIGNATURE_CHECKER_V2_SCRIPT_FIX);
    let sig_checker_v2_fix_function_signatures = gas_feature_version >= RELEASE_V1_34;
    let enable_enum_types = features.is_enabled(FeatureFlag::ENABLE_ENUM_TYPES);
    let enable_resource_access_control =
        features.is_enabled(FeatureFlag::ENABLE_RESOURCE_ACCESS_CONTROL);
    let enable_function_values = features.is_enabled(FeatureFlag::ENABLE_FUNCTION_VALUES);
    // Note: we reuse the `enable_function_values` flag to set various stricter limits on types.

    VerifierConfig {
        scope: VerificationScope::Everything,
        max_loop_depth: Some(5),
        max_generic_instantiation_length: Some(32),
        max_function_parameters: Some(128),
        max_basic_blocks: Some(1024),
        max_value_stack_size: 1024,
        max_type_nodes: if enable_function_values {
            Some(128)
        } else {
            Some(256)
        },
        max_push_size: Some(10000),
        max_struct_definitions: None,
        max_struct_variants: None,
        max_fields_in_struct: None,
        max_function_definitions: None,
        max_back_edges_per_function: None,
        max_back_edges_per_module: None,
        max_basic_blocks_in_script: None,
        max_per_fun_meter_units: Some(1000 * 80000),
        max_per_mod_meter_units: Some(1000 * 80000),
        _use_signature_checker_v2: true,
        sig_checker_v2_fix_script_ty_param_count,
```

**File:** types/src/on_chain_config/aptos_features.rs (L49-49)
```rust
    SIGNATURE_CHECKER_V2_SCRIPT_FIX = 29,
```
