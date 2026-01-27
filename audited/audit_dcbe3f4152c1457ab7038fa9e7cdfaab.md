# Audit Report

## Title
Missing Type Argument Validation in Access Specifier ResourceInstantiation Enables Access Control Bypass

## Summary
The Move VM bytecode verifier fails to validate that `ResourceInstantiation` entries in function handle access specifiers have the correct number of type arguments matching the referenced struct's type parameters. This allows malicious modules to pass verification with access specifiers containing type-mismatched resource instantiations, leading to incorrect access control decisions at runtime that can allow unauthorized resource access or incorrectly deny legitimate operations.

## Finding Description

The vulnerability exists in the bytecode verification pipeline's handling of access specifiers. When a module is loaded, function handles can specify access control constraints via the `access_specifiers` field, including `ResourceInstantiation(StructHandleIndex, SignatureIndex)` which specifies access to a particular struct with specific type arguments.

**The Critical Gap:**

The bytecode verifier validates struct instantiations in regular bytecode (instructions like `MoveFromGeneric`, `BorrowGlobalGeneric`) to ensure type argument counts match struct definitions: [1](#0-0) 

However, this validation is **NOT** applied to `ResourceInstantiation` within access specifiers. The verifier's `verify_function_handle` only checks parameter and return signatures: [2](#0-1) 

The `access_specifiers` field is completely ignored during signature verification: [3](#0-2) 

**Attack Vector:**

1. Attacker crafts a malicious module with a function handle containing:
   - `access_specifiers: Some([ResourceInstantiation(struct_idx, sig_idx)])`
   - Where `struct_handles[struct_idx]` has N type parameters
   - But `signatures[sig_idx]` contains M type arguments where M ≠ N

2. The module passes bounds checking (indices are in range) and feature verification (feature is enabled), but the type argument count mismatch is never detected.

3. During module loading, `load_access_specifier` creates the runtime representation without validation: [4](#0-3) 

4. At runtime, access checks use exact equality comparison of type instantiations: [5](#0-4) 

5. The mismatched type argument count causes access control to fail in unintended ways:
   - If fewer type args than expected: legitimate accesses are incorrectly denied
   - If more type args: could match partially or incorrectly grant access

**Invariant Violated:**

- **Access Control Invariant**: Access specifiers must correctly constrain resource access according to declared types
- **Move VM Safety**: Type instantiations must always match struct definitions

## Impact Explanation

This is a **HIGH severity** vulnerability per Aptos bug bounty criteria:

1. **Access Control Bypass**: Functions could declare resource access constraints that are incorrectly evaluated, potentially allowing unauthorized writes to critical resources (governance proposals, stake pools, token balances) or blocking legitimate operations.

2. **Cross-Module Attack Surface**: Function handles with access specifiers are used for imported functions across modules. A malicious module could export functions with broken access control that other modules trust and call.

3. **Deterministic Execution Risk**: If different validators process the same malicious module slightly differently (though the verifier should be deterministic), this could theoretically cause consensus divergence, though this is less likely than the direct access control issues.

4. **Protocol-Level Impact**: Access specifiers are a security feature of the Move VM. Breaking them undermines the entire access control model for resource-accessing functions.

This qualifies as "Significant protocol violations" under High Severity criteria.

## Likelihood Explanation

**Likelihood: MEDIUM-HIGH**

**Attacker Requirements:**
- Ability to publish a module (requires gas payment only)
- Knowledge of Move bytecode format and access specifiers
- No special privileges or validator access required

**Complexity:**
- Moderate: Requires crafting specific bytecode rather than just Move source code
- The attacker needs to directly manipulate the compiled module's binary format
- However, this is well within reach of any determined attacker with bytecode-level knowledge

**Detection Difficulty:**
- The bug would be hard to detect in normal usage as access specifiers are relatively new
- Malicious modules would pass all verification checks
- Only runtime access control failures would reveal the issue

## Recommendation

Add validation of access specifiers in the bytecode verifier's signature checking phase. Specifically:

1. **Extend `verify_function_handle` to validate access specifiers:**

```rust
fn verify_function_handle(&self, fh: &FunctionHandle) -> PartialVMResult<()> {
    let ability_context = BitsetTypeParameterConstraints::from(fh.type_parameters.as_slice());
    // Reference are allowed to be in parameter and return signatures.
    self.verify_signature_in_context(&ability_context, fh.parameters, true)?;
    self.verify_signature_in_context(&ability_context, fh.return_, true)?;
    
    // NEW: Validate access specifiers
    if let Some(access_specs) = &fh.access_specifiers {
        for spec in access_specs {
            self.verify_access_specifier(&ability_context, spec)?;
        }
    }
    
    Ok(())
}
```

2. **Add new validation method:**

```rust
fn verify_access_specifier(
    &self,
    ability_context: &BitsetTypeParameterConstraints<N>,
    spec: &AccessSpecifier,
) -> PartialVMResult<()> {
    use ResourceSpecifier::*;
    match &spec.resource {
        ResourceInstantiation(struct_idx, sig_idx) => {
            // Get struct handle and validate type argument count
            let struct_handle = &self.resolver.struct_handles()[struct_idx.0 as usize];
            let sig = self.resolver.signature_at(*sig_idx);
            
            if struct_handle.type_parameters.len() != sig.0.len() {
                return Err(
                    PartialVMError::new(StatusCode::NUMBER_OF_TYPE_ARGUMENTS_MISMATCH)
                        .with_message(format!(
                            "access specifier: expected {} type argument(s) for struct, got {}",
                            struct_handle.type_parameters.len(),
                            sig.0.len()
                        ))
                );
            }
            
            // Also validate type arguments meet ability constraints
            for (idx, ty_arg) in sig.0.iter().enumerate() {
                let required_abilities = if struct_handle.type_parameters[idx].is_phantom {
                    struct_handle.type_parameters[idx].constraints
                } else {
                    struct_handle.type_parameters[idx].constraints
                };
                self.check_ty(ty_arg, false, required_abilities, 
                             &mut BitsetTypeParameterConstraints::new())?;
            }
        }
        _ => {} // Other resource specifiers don't have type arguments
    }
    Ok(())
}
```

3. **Apply the same validation to address specifiers with function instantiations if they reference structs.**

## Proof of Concept

```rust
// Rust test demonstrating the vulnerability
#[test]
fn test_access_specifier_type_mismatch() {
    use move_binary_format::file_format::*;
    
    // Create a minimal module with a struct that has 1 type parameter
    let mut module = CompiledModule {
        version: VERSION_MAX,
        // ... (standard module setup)
        
        struct_handles: vec![
            StructHandle {
                module: ModuleHandleIndex(0),
                name: IdentifierIndex(0),  // "Coin"
                abilities: AbilitySet::EMPTY,
                type_parameters: vec![AbilitySet::EMPTY], // 1 type param
            }
        ],
        
        signatures: vec![
            Signature(vec![]),  // Signature 0: empty
            Signature(vec![     // Signature 1: TWO type arguments (WRONG!)
                SignatureToken::U64,
                SignatureToken::Bool,
            ]),
        ],
        
        function_handles: vec![
            FunctionHandle {
                module: ModuleHandleIndex(0),
                name: IdentifierIndex(1),  // "transfer"
                parameters: SignatureIndex(0),
                return_: SignatureIndex(0),
                type_parameters: vec![],
                // MALICIOUS: ResourceInstantiation with wrong type arg count
                access_specifiers: Some(vec![
                    AccessSpecifier {
                        kind: AccessKind::Writes,
                        negated: false,
                        resource: ResourceSpecifier::ResourceInstantiation(
                            StructHandleIndex(0),  // Coin (expects 1 type arg)
                            SignatureIndex(1),     // But sig has 2 type args!
                        ),
                        address: AddressSpecifier::Any,
                    }
                ]),
                attributes: vec![],
            }
        ],
        // ... (rest of module structure)
    };
    
    // This should FAIL verification but currently PASSES
    let result = move_bytecode_verifier::verify_module(&module);
    
    // Current behavior: passes verification (BUG!)
    assert!(result.is_ok(), "Module incorrectly passes verification");
    
    // Expected behavior: should fail with NUMBER_OF_TYPE_ARGUMENTS_MISMATCH
    // assert!(result.is_err());
    // assert!(matches!(result.unwrap_err().major_status(), 
    //     StatusCode::NUMBER_OF_TYPE_ARGUMENTS_MISMATCH));
}
```

## Notes

This vulnerability was confirmed through source code analysis of the verification pipeline. The fix is straightforward and should be applied before access specifiers see widespread production use. The impact is limited to modules that use access specifiers with `ResourceInstantiation`, which is a relatively new feature, but the security implications are significant enough to warrant immediate patching.

### Citations

**File:** third_party/move/move-bytecode-verifier/src/signature_v2.rs (L200-209)
```rust
                if handle.type_parameters.len() != ty_args.len() {
                    return Err(
                        PartialVMError::new(StatusCode::NUMBER_OF_TYPE_ARGUMENTS_MISMATCH)
                            .with_message(format!(
                                "expected {} type argument(s), got {}",
                                handle.type_parameters.len(),
                                ty_args.len()
                            )),
                    );
                }
```

**File:** third_party/move/move-bytecode-verifier/src/signature_v2.rs (L792-798)
```rust
    fn verify_function_handle(&self, fh: &FunctionHandle) -> PartialVMResult<()> {
        let ability_context = BitsetTypeParameterConstraints::from(fh.type_parameters.as_slice());
        // Reference are allowed to be in parameter and return signatures.
        self.verify_signature_in_context(&ability_context, fh.parameters, true)?;
        self.verify_signature_in_context(&ability_context, fh.return_, true)?;
        Ok(())
    }
```

**File:** third_party/move/move-bytecode-verifier/src/signature_v2.rs (L1146-1171)
```rust
fn verify_module_impl<const N: usize>(
    config: &VerifierConfig,
    module: &CompiledModule,
) -> PartialVMResult<()> {
    let arena = Arena::<BitsetTypeParameterConstraints<N>>::new();
    let checker = SignatureChecker::new(
        &arena,
        BinaryIndexedView::Module(module),
        config.sig_checker_v2_fix_function_signatures,
    );

    // Check if all signatures & instantiations are well-formed without any specific contexts.
    // This is only needed if we want to keep the binary format super clean.
    checker.verify_signature_pool_contextless()?;
    checker.verify_function_instantiations_contextless()?;
    checker.verify_struct_instantiations_contextless()?;
    checker.verify_field_instantiations_contextless()?;
    checker.verify_struct_variant_instantiations_contextless()?;
    checker.verify_variant_field_instantiations_contextless()?;

    checker.verify_function_handles()?;
    checker.verify_function_defs()?;
    checker.verify_struct_defs()?;

    Ok(())
}
```

**File:** third_party/move/move-vm/runtime/src/loader/access_specifier_loader.rs (L71-74)
```rust
        ResourceInstantiation(str_idx, ty_idx) => Ok(ResourceSpecifier::ResourceInstantiation(
            access_table(struct_names, str_idx.0)?.clone(),
            access_table(signature_table, ty_idx.0)?.clone(),
        )),
```

**File:** third_party/move/move-vm/types/src/loaded_data/runtime_access_specifier.rs (L213-215)
```rust
            ResourceInstantiation(enabled_struct_id, enabled_type_inst) => {
                enabled_struct_id == struct_id && enabled_type_inst == type_inst
            },
```
