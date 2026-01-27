# Audit Report

## Title
Type Parameter Count Mismatch Causes Panic in Script Composer During Generic Function Instantiation

## Summary
The `TransactionComposer::add_batched_call` function fails to validate that the number of provided type arguments matches the function's type parameter count before instantiating function signatures. This causes an unchecked array access panic in the Move binary format library when processing generic functions with mismatched type arguments.

## Finding Description

The vulnerability exists in the script-composer's `add_batched_call` method, which allows callers to compose batched Move function calls. When a caller invokes a generic function (one with type parameters), they must provide type arguments. However, the code does not validate that the number of type arguments matches the function's type parameter count. [1](#0-0) 

The attack flow is:

1. Attacker loads a valid module containing a generic function (e.g., `public fun test<T, U>(x: T)`) via `store_module`
2. Attacker calls `add_batched_call` with the function name but provides fewer type arguments than required (e.g., 0 or 1 type arguments for a function requiring 2)
3. At line 259, when the function signature tokens are instantiated via `ty.instantiate(&type_arguments)`, the code attempts to substitute type parameters
4. The `instantiate` method in the Move binary format library performs direct array indexing without bounds checking: [2](#0-1) 

Specifically, at line 1312, when encountering a `TypeParameter(idx)`, the code does `subst_mapping[*idx as usize].clone()`, which panics if `idx >= subst_mapping.len()`.

## Impact Explanation

This is a **Medium Severity** vulnerability according to the Aptos bug bounty criteria for the following reasons:

- **Service Availability**: Causes immediate panic and crash of the script-composer service or any WASM-based application using it
- **Scope**: Limited to the script-composer utility component; does not affect validator nodes, consensus, or core blockchain execution
- **Attack Complexity**: Low - attacker only needs to call the public API with crafted inputs
- **No Validation Defense**: The bytecode verifier (line 408) would catch the issue, but the panic occurs before reaching verification

While this meets "API crashes" under High Severity criteria, the limited scope (utility library rather than core consensus/validator infrastructure) and the fact that it doesn't affect blockchain state or validator operations places it at Medium Severity.

## Likelihood Explanation

**Likelihood: High**

- The vulnerable function `add_batched_call` is exposed via WASM bindings (`add_batched_call_wasm`), making it accessible to frontend applications
- No authentication or special privileges required - any caller can trigger this
- Attack is deterministic and requires no race conditions or timing dependencies
- An attacker only needs to:
  1. Identify or create any module with a generic function
  2. Call the API with incorrect type argument count
  3. Immediate crash occurs

## Recommendation

Add validation to check that the number of provided type arguments matches the function's type parameter count before calling `instantiate`:

```rust
pub fn add_batched_call(
    &mut self,
    module: String,
    function: String,
    ty_args: Vec<String>,
    args: Vec<CallArgument>,
) -> anyhow::Result<Vec<CallArgument>> {
    // ... existing code ...
    
    let type_arguments = LOADED_MODULES.with(|modules| {
        ty_args
            .iter()
            .map(|ty| import_type_tag(&mut self.builder, ty, &modules.borrow()))
            .collect::<PartialVMResult<Vec<_>>>()
    })?;

    let mut arguments = vec![];
    let expected_args_ty = {
        let script = self.builder.as_script();
        let func = script.function_handle_at(call_idx);
        
        // ADD THIS VALIDATION:
        if func.type_parameters.len() != type_arguments.len() {
            bail!(
                "Function {}::{} requires {} type arguments, but {} were provided",
                module,
                function,
                func.type_parameters.len(),
                type_arguments.len()
            );
        }
        
        // ... rest of the code ...
    };
    // ...
}
```

## Proof of Concept

```rust
#[test]
fn test_type_parameter_panic() {
    // Create a module with a generic function
    let module_source = r#"
    module 0x1::Test {
        public fun generic_func<T, U>(x: T, y: U) {
            // function body
        }
    }
    "#;
    
    // Compile the module
    let compiled_module = compile_module(module_source);
    
    // Create a TransactionComposer
    let mut composer = TransactionComposer::single_signer();
    
    // Store the module
    composer.store_module(compiled_module).unwrap();
    
    // Attempt to call the generic function with ZERO type arguments
    // (should require 2 type arguments: T and U)
    let result = composer.add_batched_call(
        "0x1::Test".to_string(),
        "generic_func".to_string(),
        vec![], // Empty type args - WRONG! Should be 2
        vec![
            CallArgument::Raw(bcs::to_bytes(&123u64).unwrap()),
            CallArgument::Raw(bcs::to_bytes(&456u64).unwrap()),
        ],
    );
    
    // This will PANIC at the instantiate() call
    // Expected: Should return an error instead of panicking
}
```

**Notes:**

- The panic occurs during type substitution when the Move binary format library tries to access `type_arguments[1]` for `TypeParameter(1)` (the `U` parameter), but the array is empty
- This vulnerability demonstrates inadequate input validation before calling unsafe (panic-prone) dependency code
- The fix requires validating type parameter counts match before instantiation

### Citations

**File:** aptos-move/script-composer/src/builder.rs (L237-261)
```rust
        let type_arguments = LOADED_MODULES.with(|modules| {
            ty_args
                .iter()
                .map(|ty| import_type_tag(&mut self.builder, ty, &modules.borrow()))
                .collect::<PartialVMResult<Vec<_>>>()
        })?;

        let mut arguments = vec![];
        let expected_args_ty = {
            let script = self.builder.as_script();
            let func = script.function_handle_at(call_idx);
            if script.signature_at(func.parameters).0.len() != args.len() {
                bail!(
                    "Function {}::{} argument call size mismatch",
                    module,
                    function
                );
            }
            script
                .signature_at(func.parameters)
                .0
                .iter()
                .map(|ty| ty.instantiate(&type_arguments))
                .collect::<Vec<_>>()
        };
```

**File:** third_party/move/move-binary-format/src/file_format.rs (L1281-1314)
```rust
    pub fn instantiate(&self, subst_mapping: &[SignatureToken]) -> SignatureToken {
        use SignatureToken::*;
        let inst_vec = |v: &[SignatureToken]| -> Vec<SignatureToken> {
            v.iter().map(|ty| ty.instantiate(subst_mapping)).collect()
        };
        match self {
            Bool => Bool,
            U8 => U8,
            U16 => U16,
            U32 => U32,
            U64 => U64,
            U128 => U128,
            U256 => U256,
            I8 => I8,
            I16 => I16,
            I32 => I32,
            I64 => I64,
            I128 => I128,
            I256 => I256,
            Address => Address,
            Signer => Signer,
            Vector(ty) => Vector(Box::new(ty.instantiate(subst_mapping))),
            Function(args, result, abilities) => {
                Function(inst_vec(args), inst_vec(result), *abilities)
            },
            Struct(idx) => Struct(*idx),
            StructInstantiation(idx, struct_type_args) => {
                StructInstantiation(*idx, inst_vec(struct_type_args))
            },
            Reference(ty) => Reference(Box::new(ty.instantiate(subst_mapping))),
            MutableReference(ty) => MutableReference(Box::new(ty.instantiate(subst_mapping))),
            TypeParameter(idx) => subst_mapping[*idx as usize].clone(),
        }
    }
```
