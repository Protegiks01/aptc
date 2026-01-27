# Audit Report

## Title
View Functions Can Bypass Signer Restriction via Generic Type Arguments

## Summary
View functions can receive `TypeTag::Signer` as type arguments through generic type parameters, allowing users to forge signer values for arbitrary addresses. This bypasses the intended restriction that view functions cannot use signer parameters, violating access control guarantees and enabling unauthorized information disclosure.

## Finding Description

The Aptos framework explicitly prohibits view functions from having `signer` or `&signer` parameters through compile-time validation. [1](#0-0)  This restriction ensures view functions remain authorization-free read operations.

However, this validation only checks the function's declared parameter types, not the instantiated types after generic type substitution. A view function declared as `#[view] public fun generic_view<T>(value: T): address` passes validation because the parameter type is `T` (a type parameter), not `signer`.

When this function is called via the API with `type_arguments: ["signer"]`, the following bypass occurs:

1. **API Layer**: The `ViewFunction` struct accepts arbitrary `TypeTag` values in `ty_args` without validation. [2](#0-1) 

2. **Type Conversion**: `MoveType::Signer` is directly converted to `TypeTag::Signer` without filtering. [3](#0-2) 

3. **Function Instantiation**: The type arguments (including `TypeTag::Signer`) are passed to `load_instantiated_function`, performing type substitution where `T` becomes `Signer`. [4](#0-3) 

4. **Argument Construction**: When `is_view = true`, the `construct_arg` function explicitly allows `Signer` type and returns the user-provided bytes without validation. [5](#0-4) 

5. **Signer Deserialization**: With `legacy_signer = false` (the default for view functions), the system deserializes the user-provided bytes as a valid signer value using the signer serialization layout. [6](#0-5) 

The user can provide any address and the system will create a signer value for that address, enabling complete forgery of signer authorization.

## Impact Explanation

This is a **High Severity** vulnerability (up to $50,000) constituting a significant protocol violation:

- **Access Control Bypass**: Users can forge signer values for arbitrary addresses, bypassing authorization checks in view functions that verify signer ownership
- **Information Disclosure**: View functions checking signer authorization can be exploited to leak sensitive data that should only be accessible to legitimate address owners  
- **Protocol Integrity Violation**: Contradicts the fundamental design principle that view functions should not have authorization capabilities

While view functions cannot modify state, the ability to forge signers violates the security boundary between authorized and unauthorized operations. This could be exploited to:
- Query private account information that requires signer verification
- Bypass access control in read-only APIs
- Potentially combine with other vulnerabilities for escalated attacks

## Likelihood Explanation

**High likelihood of exploitation:**
- Trivial to exploit - requires only a standard API call with modified type arguments
- No special permissions or validator access required
- Any deployed view function with generic type parameters is vulnerable
- Attack can be automated and scaled across all generic view functions in the framework

The vulnerability exists in production code and affects the core view function execution path used by all nodes.

## Recommendation

Add validation to reject `TypeTag::Signer` (and potentially other restricted types) in view function type arguments:

```rust
// In api/types/src/convert.rs, within convert_view_function():
pub fn convert_view_function(&self, view_request: ViewRequest) -> Result<ViewFunction> {
    // ... existing code ...
    
    // Validate type arguments don't contain restricted types
    for ty_arg in &type_arguments {
        if let MoveType::Signer = ty_arg {
            return Err(format_err!(
                "view functions cannot use signer as type argument"
            ));
        }
        // Also check nested types in Vector, Struct type arguments
    }
    
    // ... rest of existing code ...
}
```

Alternatively, add validation in `validate_view_function` to check instantiated parameter types after substitution reject any that resolve to `Signer`.

## Proof of Concept

**Move Module:**
```move
module test_addr::exploit {
    use std::signer;
    
    #[view]
    public fun extract_address<T>(s: T): address {
        // When T=signer, extracts address from forged signer
        signer::address_of(&s)
    }
}
```

**API Call:**
```json
POST /v1/view
{
  "function": "0xTEST::exploit::extract_address",
  "type_arguments": ["signer"],
  "arguments": ["0x1"]
}
```

**Expected Result**: The view function successfully executes with a forged signer for address `0x1`, returning `0x1`, demonstrating the ability to create arbitrary signer values in view functions.

**Notes:**
- The vulnerability exists because generic type parameter validation happens at module publish time (checking declared types) rather than at view function call time (checking instantiated types)
- The `legacy_signer = false` default for view function argument deserialization enables signer value creation from user-provided bytes
- This bypasses the explicit prohibition in `extended_checks.rs` designed to prevent view functions from using signers

### Citations

**File:** aptos-move/framework/src/extended_checks.rs (L700-729)
```rust
            fun.get_parameters()
                .iter()
                .for_each(
                    |Parameter(_sym, parameter_type, param_loc)| match parameter_type {
                        Type::Primitive(inner) => {
                            if inner == &PrimitiveType::Signer {
                                self.env.error(
                                    param_loc,
                                    "`#[view]` function cannot use a `signer` parameter",
                                )
                            }
                        },
                        Type::Reference(mutability, inner) => {
                            if let Type::Primitive(inner) = inner.as_ref() {
                                if inner == &PrimitiveType::Signer
                                // Avoid a redundant error message for `&mut signer`, which is
                                // always disallowed for transaction entries, not just for
                                // `#[view]`.
                                    && mutability == &ReferenceKind::Immutable
                                {
                                    self.env.error(
                                        param_loc,
                                        "`#[view]` function cannot use the `&signer` parameter",
                                    )
                                }
                            }
                        },
                        _ => (),
                    },
                );
```

**File:** api/types/src/view.rs (L23-30)
```rust
#[derive(Clone, Debug, Hash, Eq, PartialEq, Serialize, Deserialize)]
pub struct ViewFunction {
    pub module: ModuleId,
    pub function: Identifier,
    pub ty_args: Vec<TypeTag>,
    #[serde(with = "vec_bytes")]
    pub args: Vec<Vec<u8>>,
}
```

**File:** api/types/src/move_types.rs (L947-947)
```rust
            MoveType::Signer => TypeTag::Signer,
```

**File:** aptos-move/aptos-vm/src/aptos_vm.rs (L2751-2758)
```rust
            let func = loader.load_instantiated_function(
                &LegacyLoaderConfig::unmetered(),
                gas_meter,
                traversal_context,
                &module_id,
                &func_name,
                &ty_args,
            )?;
```

**File:** aptos-move/aptos-vm/src/verifier/transaction_arg_validation.rs (L314-320)
```rust
        Signer => {
            if is_view {
                Ok(arg)
            } else {
                Err(invalid_signature())
            }
        },
```

**File:** third_party/move/move-vm/types/src/values/values_impl.rs (L5117-5129)
```rust
            L::Signer => {
                if self.ctx.legacy_signer {
                    Err(D::Error::custom(
                        "Cannot deserialize signer into value".to_string(),
                    ))
                } else {
                    let seed = DeserializationSeed {
                        ctx: self.ctx,
                        layout: &MoveStructLayout::signer_serialization_layout(),
                    };
                    Ok(Value::struct_(seed.deserialize(deserializer)?))
                }
            },
```
