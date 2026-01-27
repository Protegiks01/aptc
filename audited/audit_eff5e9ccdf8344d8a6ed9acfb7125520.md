# Audit Report

## Title
View Function Signer Parameter Validation Bypass via Type Parameters

## Summary
The compile-time validation in `check_and_record_view_functions()` allows view functions to accept unconstrained generic type parameters that can be instantiated with `signer` at runtime, bypassing the explicit restriction that view functions cannot accept signer parameters.

## Finding Description

View functions in Aptos are read-only functions that should not require authentication. The framework explicitly prohibits view functions from accepting `signer` or `&signer` parameters. [1](#0-0) 

However, the validation in `check_and_record_view_functions()` has a gap. At line 694, it calls `check_transaction_args()` which allows `TypeParameter(_)` without restrictions. [2](#0-1) 

The function `check_transaction_input_type()` explicitly allows type parameters: [3](#0-2) 

While there's an additional check for explicit signer types (lines 700-729), this check only examines `Type::Primitive(PrimitiveType::Signer)` and `Type::Reference(...)` patterns, not type parameters that could later be instantiated with signer. [4](#0-3) 

At runtime, the validation logic contradicts the compile-time intent. The `construct_arg()` function allows `Signer` type when `is_view=true`: [5](#0-4) 

**Attack Path:**
1. Deploy a module with: `#[view] public fun generic_view<T>(param: T): u64 { ... }`
2. The compile-time check allows it (type parameter passes validation)
3. At runtime, call the function with type argument `T=signer`
4. The VM accepts it due to the `is_view=true` logic

## Impact Explanation

This finding represents a **validation inconsistency** rather than a critical security vulnerability. While it violates the stated restriction that view functions cannot accept signer parameters, the practical exploitability is severely limited:

1. **Move Type System Constraint**: A generic function `<T>` cannot call signer-specific operations like `signer::address_of()` on a value of type `T` because the function doesn't know the concrete type at compile time.

2. **Read-Only Nature**: View functions cannot modify blockchain state, limiting potential harm.

3. **No Direct Authentication Bypass**: There's no clear path to using this for authentication bypass or privilege escalation.

The severity is **Low to Medium** - it's a validation gap that violates documented invariants and creates confusion, but lacks a concrete exploitation path leading to funds loss, consensus violation, or state corruption as required by higher severity categories.

## Likelihood Explanation

**Likelihood: Medium** - Developers could inadvertently create view functions with unconstrained type parameters, and such modules would be accepted by the current validation. However, the practical impact of such modules is limited by Move's type system constraints.

## Recommendation

Add explicit validation for type parameters in view function parameters. The check should ensure type parameters either:
- Are not used directly as function parameters, OR  
- Have ability constraints that prevent signer instantiation (e.g., require `copy` or `store` abilities, which `signer` lacks - as `signer` only has `drop` ability) [6](#0-5) 

Additionally, review the runtime logic at lines 314-320 of `transaction_arg_validation.rs`, as allowing `Signer` for view functions contradicts the compile-time restriction.

## Proof of Concept

```move
module 0xCAFE::ViewBypass {
    #[view]
    public fun generic_view<T>(param: T): u64 {
        // This compiles successfully despite T potentially being signer
        // However, we cannot call signer::address_of(param) here
        // because the function doesn't know T=signer at compile time
        42
    }
}
```

Deploy this module, then call `generic_view<signer>(signer_bytes)` - the runtime will accept it, demonstrating the validation bypass, though practical exploitation remains limited by type system constraints.

---

**Notes:**

This finding identifies a real validation gap where view functions can accept type parameters that may be instantiated with `signer` at runtime, bypassing the explicit compile-time restriction. However, the security impact is limited by Move's type system, which prevents generic functions from performing type-specific operations on their type parameters. This represents more of a validation consistency issue than an immediately exploitable critical vulnerability.

### Citations

**File:** aptos-move/e2e-move-tests/src/tests/attributes.rs (L37-55)
```rust
#[test]
#[should_panic]
fn test_view_attribute_with_signer() {
    let mut h = MoveHarness::new();
    let account = h.new_account_at(AccountAddress::from_hex_literal("0xf00d").unwrap());

    let mut builder = PackageBuilder::new("Package");
    builder.add_source(
        "m.move",
        r#"
        module 0xf00d::M {
            #[view]
            fun view(_:signer,value: u64): u64 { value }
        }
        "#,
    );
    let path = builder.write_to_temp().unwrap();
    h.create_publish_package(&account, path.path(), None, |_| {});
}
```

**File:** aptos-move/framework/src/extended_checks.rs (L244-247)
```rust
        match ty {
            Primitive(_) | TypeParameter(_) => {
                // Any primitive type allowed, any parameter expected to instantiate with primitive
            },
```

**File:** aptos-move/framework/src/extended_checks.rs (L694-694)
```rust
            self.check_transaction_args(&fun.get_parameters());
```

**File:** aptos-move/framework/src/extended_checks.rs (L703-729)
```rust
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

**File:** third_party/move/move-core/types/src/ability.rs (L116-117)
```rust
    /// Abilities for `Signer`
    pub const SIGNER: AbilitySet = Self(Ability::Drop as u8);
```
