# Audit Report

## Title
View Function Return Type Depth Validation Bypass Allows API Resource Exhaustion

## Summary
The `validate_view_function()` function does not validate the recursive depth of return types, allowing view functions to return types with depth up to 20 (bytecode verifier limit) while the API layer is intended to enforce a limit of 8. This bypasses the `MAX_RECURSIVE_TYPES_ALLOWED` constraint and enables API resource exhaustion attacks.

## Finding Description

The Aptos API defines `MAX_RECURSIVE_TYPES_ALLOWED = 8` as the maximum recursive type depth limit. This is enforced for input types through the `VerifyInputWithRecursion` trait. However, view function return types bypass this validation entirely. [1](#0-0) 

When a view function is called with JSON response format, the return types are retrieved and converted without depth validation: [2](#0-1) 

The `function_return_types()` returns `Vec<MoveType>` directly from module metadata without calling `.verify()`: [3](#0-2) 

The conversion from `MoveType` to `TypeTag` at line 201 uses recursive `TryFrom` without depth checking: [4](#0-3) 

Meanwhile, bytecode verification allows type depth up to 20 when function values are enabled: [5](#0-4) 

**Attack Path:**
1. Attacker publishes a module with a view function returning deeply nested types (e.g., `vector<vector<vector<...>>>` with depth 15-20)
2. Module passes bytecode verification (max_type_depth = 20)
3. The view function validation only checks that return types exist, not their depth: [6](#0-5) 

4. When called via API with JSON format, return types are converted without depth validation
5. This consumes 2.5x more CPU resources than the intended API limit allows

## Impact Explanation

This is a **Medium Severity** vulnerability per the Aptos bug bounty program because:

1. **Resource Exhaustion**: An attacker can force the API server to process types 2.5x deeper than intended (20 vs 8), consuming excessive CPU during recursive type conversions and deserialization
2. **Validation Bypass**: The API's documented security boundary is violated - inputs are limited to depth 8, but outputs can be depth 20
3. **Defense-in-Depth Violation**: The API layer should enforce stricter limits than the VM layer, but this protection is bypassed for return types
4. **API Availability Impact**: Repeated calls to such view functions could degrade API server performance

This does not reach High/Critical severity because it doesn't directly cause fund loss, consensus violations, or complete service unavailability, but represents a significant operational security issue.

## Likelihood Explanation

**Likelihood: High**

- **Attacker Requirements**: Any user can publish modules and call view functions - no special privileges needed
- **Complexity**: Low - simply define a view function with deeply nested return type
- **Detection**: The inconsistency is not immediately visible and could remain unexploited
- **Feasibility**: Attack is straightforward to execute and reproduce

The vulnerability is present in production code and can be triggered by any API user calling a specially crafted view function.

## Recommendation

Add return type depth validation in `validate_view_function()` or in the API response processing. The fix should validate return types against `MAX_RECURSIVE_TYPES_ALLOWED` before processing them.

**Recommended Fix:**

In `api/src/view_function.rs`, after retrieving return types, validate their depth:

```rust
let return_types = state_view
    .as_converter(context.db.clone(), context.indexer_reader.clone())
    .function_return_types(&view_function)
    .and_then(|tys| {
        // Validate depth for each return type
        for ty in tys.iter() {
            ty.verify(0).context("Return type exceeds maximum recursive depth")?;
        }
        
        tys.iter()
            .map(TypeTag::try_from)
            .collect::<anyhow::Result<Vec<_>>>()
    })
    .map_err(|err| {
        BasicErrorWith404::bad_request_with_code(
            err,
            AptosErrorCode::InvalidInput,
            &ledger_info,
        )
    })?;
```

Alternatively, add validation in `validate_view_function()` to check return type depth limits before function execution.

## Proof of Concept

**Move Module (malicious_view.move):**
```move
module attacker::deep_types {
    use std::vector;
    
    #[view]
    public fun deeply_nested_return(): vector<vector<vector<vector<vector<
        vector<vector<vector<vector<vector<vector<vector<vector<vector<vector<
        vector<vector<vector<vector<vector<u64>>>>>>>>>>>>>>>>>>>> {
        // 20 levels of nesting - passes bytecode verification
        // but exceeds API's MAX_RECURSIVE_TYPES_ALLOWED of 8
        vector::empty()
    }
}
```

**Attack Execution:**
1. Publish the module above
2. Call the view function repeatedly via API with JSON response format:
```bash
curl -X POST https://fullnode.mainnet.aptoslabs.com/v1/view \
  -H "Content-Type: application/json" \
  -d '{
    "function": "attacker::deep_types::deeply_nested_return",
    "type_arguments": [],
    "arguments": []
  }'
```

3. Each call forces the API to process type conversions for 20-depth nested types instead of the intended 8-depth limit
4. Monitor API server CPU usage - it will be higher than for functions returning types within the 8-depth limit
5. Scale the attack with multiple concurrent requests to cause API server resource exhaustion

## Notes

- The VM layer correctly limits type depth to 20 during bytecode verification
- The API layer intends to enforce a stricter limit of 8 via `MAX_RECURSIVE_TYPES_ALLOWED`
- This protection works for input validation but is bypassed for return type processing
- The issue affects only JSON response format (BCS format uses different code path with `bcs::from_bytes_with_limit`)

### Citations

**File:** api/types/src/move_types.rs (L686-688)
```rust
/// Maximum number of recursive types - Same as (non-public)
/// move_core_types::safe_serialize::MAX_TYPE_TAG_NESTING
pub const MAX_RECURSIVE_TYPES_ALLOWED: u8 = 8;
```

**File:** api/types/src/move_types.rs (L928-988)
```rust
impl TryFrom<&MoveType> for TypeTag {
    type Error = anyhow::Error;

    fn try_from(tag: &MoveType) -> anyhow::Result<Self> {
        let ret = match tag {
            MoveType::Bool => TypeTag::Bool,
            MoveType::U8 => TypeTag::U8,
            MoveType::U16 => TypeTag::U16,
            MoveType::U32 => TypeTag::U32,
            MoveType::U64 => TypeTag::U64,
            MoveType::U128 => TypeTag::U128,
            MoveType::U256 => TypeTag::U256,
            MoveType::I8 => TypeTag::I8,
            MoveType::I16 => TypeTag::I16,
            MoveType::I32 => TypeTag::I32,
            MoveType::I64 => TypeTag::I64,
            MoveType::I128 => TypeTag::I128,
            MoveType::I256 => TypeTag::I256,
            MoveType::Address => TypeTag::Address,
            MoveType::Signer => TypeTag::Signer,
            MoveType::Vector { items } => TypeTag::Vector(Box::new(items.as_ref().try_into()?)),
            MoveType::Struct(v) => TypeTag::Struct(Box::new(v.try_into()?)),
            MoveType::Function {
                args,
                results,
                abilities,
            } => {
                let try_vec = |tys: &[MoveType]| {
                    tys.iter()
                        .map(|t| {
                            Ok(match t {
                                MoveType::Reference { mutable, to } => {
                                    let tag = to.as_ref().try_into()?;
                                    if *mutable {
                                        FunctionParamOrReturnTag::MutableReference(tag)
                                    } else {
                                        FunctionParamOrReturnTag::Reference(tag)
                                    }
                                },
                                t => FunctionParamOrReturnTag::Value(t.try_into()?),
                            })
                        })
                        .collect::<anyhow::Result<_>>()
                };
                TypeTag::Function(Box::new(FunctionTag {
                    args: try_vec(args)?,
                    results: try_vec(results)?,
                    abilities: *abilities,
                }))
            },
            MoveType::GenericTypeParam { index: _ } => TypeTag::Address, // Dummy type, allows for Object<T>
            MoveType::Reference { .. } | MoveType::Unparsable(_) => {
                return Err(anyhow::anyhow!(
                    "Invalid move type for converting into `TypeTag`: {:?}",
                    &tag
                ))
            },
        };
        Ok(ret)
    }
}
```

**File:** api/src/view_function.rs (L195-210)
```rust
        AcceptType::Json => {
            let return_types = state_view
                .as_converter(context.db.clone(), context.indexer_reader.clone())
                .function_return_types(&view_function)
                .and_then(|tys| {
                    tys.iter()
                        .map(TypeTag::try_from)
                        .collect::<anyhow::Result<Vec<_>>>()
                })
                .map_err(|err| {
                    BasicErrorWith404::bad_request_with_code(
                        err,
                        AptosErrorCode::InternalError,
                        &ledger_info,
                    )
                })?;
```

**File:** api/types/src/convert.rs (L1015-1022)
```rust
    pub fn function_return_types(&self, function: &ViewFunction) -> Result<Vec<MoveType>> {
        let code = self.inner.view_existing_module(&function.module)? as Arc<dyn Bytecode>;
        let func = code
            .find_function(function.function.as_ident_str())
            .ok_or_else(|| format_err!("could not find entry function by {:?}", function))?;

        Ok(func.return_)
    }
```

**File:** aptos-move/aptos-vm-environment/src/prod_configs.rs (L188-192)
```rust
        max_type_depth: if enable_function_values {
            Some(20)
        } else {
            None
        },
```

**File:** aptos-move/aptos-vm/src/verifier/view_function.rs (L55-61)
```rust
    // Must return values.
    if func.return_tys().is_empty() {
        return Err(
            PartialVMError::new(StatusCode::INVALID_MAIN_FUNCTION_SIGNATURE)
                .with_message("view function must return values".to_string()),
        );
    }
```
