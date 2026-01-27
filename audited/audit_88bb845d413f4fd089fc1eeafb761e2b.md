# Audit Report

## Title
Feature Flag Bypass via Incomplete Nested Type Verification in Struct Fields

## Summary
The `FeatureVerifier` in `features.rs` fails to check nested `SignatureToken::Function` types within struct field definitions when `enable_function_values` is disabled. This allows modules to bypass feature flag enforcement by embedding function types inside compound types like `Vector<Function(...)>`, violating the feature rollout control mechanism.

## Finding Description

The `FeatureVerifier::verify_struct_defs()` function performs inconsistent signature token validation compared to `verify_signatures()`. When `enable_function_values` is disabled, the verifier should reject any use of function types, but it only checks the top-level signature token of struct fields. [1](#0-0) 

The `verify_field_definition()` function calls `verify_signature_token()` directly on the field's type without traversing nested tokens: [2](#0-1) 

The `verify_signature_token()` only checks if the current token is a `Function`, not nested types within compound types like `Vector`, `Struct`, or `StructInstantiation`.

In contrast, `verify_signatures()` properly uses `preorder_traversal()` to check all nested tokens: [3](#0-2) 

This inconsistency allows an attacker to define a struct like:
```move
struct Exploit {
    field: vector<|u64| u64>  // Function type nested in Vector
}
```

When `enable_function_values = false`, the verification flow:
1. `verify_signatures()` checks the signature pool, but struct field types may not be in the pool (they're embedded in `FieldDefinition`)
2. `verify_struct_defs()` calls `verify_field_definition()` → `verify_signature_token(Vector(Function(...)))`
3. `verify_signature_token()` checks if token matches `Function` - it's a `Vector`, so it passes
4. The nested `Function` type is never detected

The `signature_v2` verifier (called later in the pipeline) validates type structure and abilities but does NOT check the `enable_function_values` feature flag: [4](#0-3) 

## Impact Explanation

**Severity: HIGH** - Significant protocol violation

This vulnerability violates the feature flag contract that controls the `enable_function_values` feature rollout: [5](#0-4) 

When the feature is disabled network-wide, function types should be completely prohibited. This bypass allows:

1. **Feature Rollout Violation**: Modules containing function types can be published before the feature is enabled, breaking the controlled rollout mechanism
2. **VM Assumption Violations**: Code paths may assume function types don't exist when the feature is disabled, potentially causing unexpected behavior
3. **Type System Inconsistency**: The type exists in bytecode but cannot be instantiated (since `PackClosure` instructions are still checked), creating a partially-valid state

While the attacker cannot create executable function values (bytecode checks remain), the presence of function types in published modules during feature rollback could complicate network upgrades or cause validation inconsistencies.

## Likelihood Explanation

**Likelihood: MEDIUM**

The attack requires:
- Network state where `enable_function_values` is disabled (during feature rollout or rollback)
- Ability to publish a module (requires gas payment and basic access)
- Knowledge of the verification bypass

The attack is straightforward to execute - simply define a struct with nested function types. However, the window of opportunity is limited to periods when the feature flag is disabled, which may be rare on mainnet.

## Recommendation

Modify `verify_field_definition()` to traverse nested signature tokens using `preorder_traversal()`, matching the behavior of `verify_signatures()`:

```rust
fn verify_field_definition(
    &self,
    struct_idx: usize,
    field: &FieldDefinition,
) -> PartialVMResult<()> {
    // Use preorder_traversal to check ALL nested tokens
    for token in field.signature.0.preorder_traversal() {
        self.verify_signature_token(token)
            .map_err(|e| e.at_index(IndexKind::StructDefinition, struct_idx as u16))?;
    }
    Ok(())
}
```

This ensures consistent verification of function types regardless of nesting depth.

## Proof of Concept

```rust
// Test in third_party/move/move-bytecode-verifier/tests/features_tests.rs
#[test]
fn test_nested_function_type_in_struct_field() {
    use move_binary_format::file_format::*;
    use move_bytecode_verifier::{FeatureVerifier, VerifierConfig};
    
    let mut module = empty_module();
    
    // Create struct with Vector<Function> field when feature disabled
    let vector_of_function = SignatureToken::Vector(Box::new(
        SignatureToken::Function(
            vec![SignatureToken::U64],
            vec![SignatureToken::U64],
            AbilitySet::EMPTY
        )
    ));
    
    module.struct_defs.push(StructDefinition {
        struct_handle: StructHandleIndex(0),
        field_information: StructFieldInformation::Declared(vec![
            FieldDefinition {
                name: IdentifierIndex(0),
                signature: TypeSignature(vector_of_function),
            }
        ]),
    });
    
    let mut config = VerifierConfig::default();
    config.enable_function_values = false; // Feature DISABLED
    
    // This should FAIL but currently PASSES due to the bug
    let result = FeatureVerifier::verify_module(&config, &module);
    
    assert!(result.is_err(), "Should reject nested function type when feature disabled");
}
```

**Notes:**
While this is a genuine verification bypass, its practical exploitability is limited because:
1. The attacker cannot create function value instances (bytecode-level checks remain)
2. The type exists but cannot be meaningfully used
3. No direct path to funds loss or consensus violation

However, it represents a significant protocol violation that could complicate feature rollouts and potentially enable future attack chains if combined with other vulnerabilities.

### Citations

**File:** third_party/move/move-bytecode-verifier/src/features.rs (L99-106)
```rust
    fn verify_field_definition(
        &self,
        struct_idx: usize,
        field: &FieldDefinition,
    ) -> PartialVMResult<()> {
        self.verify_signature_token(&field.signature.0)
            .map_err(|e| e.at_index(IndexKind::StructDefinition, struct_idx as u16))
    }
```

**File:** third_party/move/move-bytecode-verifier/src/features.rs (L159-171)
```rust
    fn verify_signatures(&self) -> PartialVMResult<()> {
        if !self.config.enable_function_values {
            for (idx, sig) in self.code.signatures().iter().enumerate() {
                for tok in &sig.0 {
                    for t in tok.preorder_traversal() {
                        self.verify_signature_token(t)
                            .map_err(|e| e.at_index(IndexKind::Signature, idx as u16))?
                    }
                }
            }
        }
        Ok(())
    }
```

**File:** third_party/move/move-bytecode-verifier/src/features.rs (L173-180)
```rust
    fn verify_signature_token(&self, tok: &SignatureToken) -> PartialVMResult<()> {
        if !self.config.enable_function_values && matches!(tok, SignatureToken::Function(..)) {
            Err(PartialVMError::new(StatusCode::FEATURE_NOT_ENABLED)
                .with_message("function value feature not enabled".to_string()))
        } else {
            Ok(())
        }
    }
```

**File:** third_party/move/move-bytecode-verifier/src/signature_v2.rs (L172-187)
```rust
            Function(params, results, abilities) => {
                assert_abilities(*abilities, required_abilities)?;
                if self.sig_checker_v2_fix_function_signatures {
                    for ty in params.iter().chain(results) {
                        self.check_ty(
                            ty,
                            // Immediate params and returns can be references.
                            true,
                            // Note we do not need to check abilities of argument or result types,
                            // they do not matter for the `required_abilities`.
                            AbilitySet::EMPTY,
                            param_constraints,
                        )?
                    }
                }
            },
```

**File:** aptos-move/aptos-vm-environment/src/prod_configs.rs (L145-153)
```rust
pub fn aptos_prod_verifier_config(gas_feature_version: u64, features: &Features) -> VerifierConfig {
    let sig_checker_v2_fix_script_ty_param_count =
        features.is_enabled(FeatureFlag::SIGNATURE_CHECKER_V2_SCRIPT_FIX);
    let sig_checker_v2_fix_function_signatures = gas_feature_version >= RELEASE_V1_34;
    let enable_enum_types = features.is_enabled(FeatureFlag::ENABLE_ENUM_TYPES);
    let enable_resource_access_control =
        features.is_enabled(FeatureFlag::ENABLE_RESOURCE_ACCESS_CONTROL);
    let enable_function_values = features.is_enabled(FeatureFlag::ENABLE_FUNCTION_VALUES);
    // Note: we reuse the `enable_function_values` flag to set various stricter limits on types.
```
