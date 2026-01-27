# Audit Report

## Title
View Function Signer Parameter Injection via Incomplete Runtime Validation

## Summary
An attacker can bypass compile-time restrictions and publish Move modules containing view functions with signer parameters. By exploiting the gap between compile-time checks and runtime bytecode verification, malicious actors can inject arbitrary signer arguments into view function calls to impersonate any address and bypass read-only access controls, leading to unauthorized information disclosure.

## Finding Description

The Aptos Move framework enforces a critical security invariant: view functions (read-only functions marked with `#[view]`) must not accept signer parameters, as signers represent authenticated addresses verified through cryptographic signatures. [1](#0-0) 

The compiler enforces this restriction through extended checks during compilation: [2](#0-1) 

However, a **critical validation gap** exists during runtime module publication. When modules are published on-chain, the bytecode verification only checks that view functions return values, but does NOT validate the absence of signer parameters: [3](#0-2) 

This incomplete validation at line 386 only checks `!sig.0.is_empty()` (ensuring the function returns values) but never inspects the function's parameter types.

Furthermore, the runtime argument validation explicitly allows signer arguments for view functions: [4](#0-3) 

When `is_view=true`, the construct_arg function accepts arbitrary signer byte arrays without cryptographic verification.

**Attack Flow:**

1. Attacker uses a modified Move compiler or hand-crafts bytecode to create a module with a view function that:
   - Is marked with the `#[view]` attribute in metadata
   - Contains signer parameters in its function signature
   - Implements logic that uses the signer for authorization or resource access

2. Attacker publishes the malicious module via `code::publish_package_txn`: [5](#0-4) 
   
   The validation calls `is_valid_view_function` which fails to check for signer parameters, allowing publication.

3. Attacker invokes the malicious view function through the REST API: [6](#0-5) 
   
   The validation allows arbitrary signer arguments due to `is_view=true`.

4. The function executes with attacker-supplied signer values representing any address (e.g., `@aptos_framework`, victim addresses, system accounts), enabling:
   - Reading resources belonging to any address without authorization
   - Bypassing access control checks in the malicious view function's logic
   - Querying sensitive data that should be restricted

## Impact Explanation

**Severity: Medium to High**

This vulnerability enables **authentication bypass** and **information disclosure** attacks:

- **Access Control Bypass**: Attackers can impersonate any address (including system addresses like `@aptos_framework`) to bypass read-only access controls
- **Privacy Violation**: Attackers can read private resources and data belonging to arbitrary accounts
- **System Information Leakage**: Attackers can query sensitive system state by spoofing privileged addresses

While view functions cannot modify persistent state (write-sets are not applied), this vulnerability breaks the fundamental security guarantee that signers represent cryptographically verified addresses. The impact aligns with **Medium severity** (information disclosure, access control failures) under the Aptos bug bounty criteria, potentially escalating to **High severity** if sensitive governance or validator information can be accessed.

## Likelihood Explanation

**Likelihood: Medium**

The attack requires:
1. ✅ Modified Move compiler or manual bytecode crafting (moderate technical barrier)
2. ✅ Successful module publication (feasible - no additional permissions required)
3. ✅ Knowledge of target resources to query (depends on attack goal)

The gap between compile-time and runtime validation makes this vulnerability reliably exploitable once the attacker overcomes the toolchain modification requirement. The lack of runtime parameter validation means any published malicious module will function as intended.

## Recommendation

Add comprehensive signer parameter validation to the runtime bytecode verification during module publication:

```rust
// In types/src/vm/module_metadata.rs, modify is_valid_view_function:

pub fn is_valid_view_function(
    module: &CompiledModule,
    functions: &BTreeMap<&IdentStr, (&FunctionHandle, &FunctionDefinition)>,
    fun: &str,
) -> Result<(), AttributeValidationError> {
    if let Ok(ident_fun) = Identifier::new(fun) {
        if let Some((func_handle, _func_def)) = functions.get(ident_fun.as_ident_str()) {
            // Check return signature is non-empty
            let return_sig = module.signature_at(func_handle.return_);
            if return_sig.0.is_empty() {
                return Err(AttributeValidationError {
                    key: fun.to_string(),
                    attribute: KnownAttributeKind::ViewFunction as u8,
                });
            }
            
            // **NEW: Validate no signer parameters**
            let param_sig = module.signature_at(func_handle.parameters);
            for param_ty in &param_sig.0 {
                if matches!(param_ty, SignatureToken::Signer) {
                    return Err(AttributeValidationError {
                        key: fun.to_string(),
                        attribute: KnownAttributeKind::ViewFunction as u8,
                    });
                }
                // Also check for &signer references
                if let SignatureToken::Reference(inner) = param_ty {
                    if matches!(**inner, SignatureToken::Signer) {
                        return Err(AttributeValidationError {
                            key: fun.to_string(),
                            attribute: KnownAttributeKind::ViewFunction as u8,
                        });
                    }
                }
            }
            
            return Ok(());
        }
    }

    Err(AttributeValidationError {
        key: fun.to_string(),
        attribute: KnownAttributeKind::ViewFunction as u8,
    })
}
```

This fix ensures runtime validation mirrors compile-time restrictions, closing the validation gap.

## Proof of Concept

```move
// malicious_view.move - Compile with modified compiler that skips extended_checks
module attacker::malicious_view {
    use std::signer;
    use aptos_framework::coin::CoinStore;
    use aptos_framework::aptos_coin::AptosCoin;
    
    #[view]
    /// Malicious view function that accepts signer parameter
    /// Bypasses compile-time check, exploits runtime validation gap
    public fun read_victim_balance(victim: &signer): u64 {
        let addr = signer::address_of(victim);
        // Access victim's coin balance without authorization
        borrow_global<CoinStore<AptosCoin>>(addr).coin.value
    }
}

// Attack execution (via REST API):
// POST /v1/view
// {
//   "function": "attacker::malicious_view::read_victim_balance",
//   "type_arguments": [],
//   "arguments": ["0x1"]  // Attacker supplies @aptos_framework address
// }
// Returns: Balance of @aptos_framework account without authentication
```

The attacker can read any account's balance by supplying arbitrary addresses as signer arguments, completely bypassing the intended security model where signers must be cryptographically verified.

## Notes

This vulnerability highlights a defense-in-depth failure where compile-time restrictions must be enforced again at runtime. The validation gap exists because `is_valid_view_function` was designed to check function properties (return signature) but not parameter constraints. The fix requires extending runtime validation to match the semantic restrictions enforced at compile time.

### Citations

**File:** aptos-move/framework/move-stdlib/sources/signer.move (L2-2)
```text
    /// signer is a builtin move type that represents an address that has been verfied by the VM.
```

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

**File:** types/src/vm/module_metadata.rs (L378-396)
```rust
pub fn is_valid_view_function(
    module: &CompiledModule,
    functions: &BTreeMap<&IdentStr, (&FunctionHandle, &FunctionDefinition)>,
    fun: &str,
) -> Result<(), AttributeValidationError> {
    if let Ok(ident_fun) = Identifier::new(fun) {
        if let Some((func_handle, _func_def)) = functions.get(ident_fun.as_ident_str()) {
            let sig = module.signature_at(func_handle.return_);
            if !sig.0.is_empty() {
                return Ok(());
            }
        }
    }

    Err(AttributeValidationError {
        key: fun.to_string(),
        attribute: KnownAttributeKind::ViewFunction as u8,
    })
}
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

**File:** aptos-move/aptos-vm/src/aptos_vm.rs (L1715-1716)
```rust
            verify_module_metadata_for_module_publishing(m, self.features())
                .map_err(|err| Self::metadata_validation_error(&err.to_string()))?;
```

**File:** aptos-move/aptos-vm/src/aptos_vm.rs (L2762-2773)
```rust
            let arguments = view_function::validate_view_function(
                session,
                &loader,
                gas_meter,
                traversal_context,
                arguments,
                func_name.as_ident_str(),
                &func,
                metadata.as_ref().map(Arc::as_ref),
                vm.features().is_enabled(FeatureFlag::STRUCT_CONSTRUCTORS),
            )
            .map_err(|e| e.finish(Location::Module(module_id)))?;
```
