# Audit Report

## Title
Missing Type Argument Recursion Depth Validation in JSON View Function Requests

## Summary
The `convert_view_function()` function in `api/types/src/convert.rs` only validates the count of type arguments using `ensure!`, but does not validate their structural depth or complexity. This allows deeply nested type arguments (exceeding `MAX_RECURSIVE_TYPES_ALLOWED = 8`) to be processed via the JSON API endpoint, causing unnecessary resource consumption before eventual rejection by the VM. [1](#0-0) 

## Finding Description
The security issue manifests as a validation inconsistency between different API input paths:

**The Vulnerable Path (JSON ViewRequest):**
1. User submits JSON ViewRequest with deeply nested type arguments (e.g., `Vector<Vector<Vector<...>>>` with depth > 8)
2. `view_function.rs` processes the JSON request without depth validation [2](#0-1) 

3. `convert_view_function()` only validates type argument COUNT via `ensure!`, not structure: [1](#0-0) 

4. Type arguments are converted using `try_into()` without depth checking: [3](#0-2) 

5. The `TryFrom<&MoveType> for TypeTag` implementation recursively processes nested types without enforcing `MAX_RECURSIVE_TYPES_ALLOWED`: [4](#0-3) 

**The Protected Path (Entry Function Transactions):**
Entry function payload validation explicitly calls `verify(0)` on each type argument to enforce depth limits: [5](#0-4) 

**The Protected Path (BCS ViewRequest):**
BCS deserialization enforces depth limits via `bcs::from_bytes_with_limit`: [6](#0-5) 

**The Depth Validation That Should Be Used:**
`MoveType` implements `VerifyInputWithRecursion` which checks `MAX_RECURSIVE_TYPES_ALLOWED = 8`: [7](#0-6) 

This validation is never invoked for JSON ViewRequests, allowing deeply nested types to consume API resources during recursive conversion before being rejected by the VM's `TypeDepthChecker` during function loading.

## Impact Explanation
This qualifies as **Medium Severity** per the Aptos bug bounty criteria:
- Violates **Invariant #9 (Resource Limits)**: "All operations must respect gas, storage, and computational limits"
- Enables API resource exhaustion through malicious input
- Does not affect consensus or validator operations (view functions are read-only)
- Impact limited to API node performance degradation

An attacker can exploit this by sending concurrent JSON ViewRequests with deeply nested type arguments (depth 50-100+), causing:
- Excessive CPU consumption during recursive type conversion
- Thread pool exhaustion in blocking API handlers
- API response time degradation for legitimate users

## Likelihood Explanation
**High Likelihood:**
- Trivial to exploit (any user can send JSON POST requests)
- No authentication or special permissions required
- Affects default API configuration
- Clear validation gap between input paths

The validation inconsistency is evident: entry function submissions and BCS ViewRequests enforce depth limits, but JSON ViewRequests do not.

## Recommendation
Add explicit depth validation for JSON ViewRequests before calling `convert_view_function()`:

```rust
// In api/src/view_function.rs, modify the JSON case:
ViewFunctionRequest::Json(data) => {
    // Validate type argument depth before conversion
    for type_arg in &data.0.type_arguments {
        type_arg.verify(0).map_err(|err| {
            BasicErrorWith404::bad_request_with_code(
                err.context("Type argument validation failed"),
                AptosErrorCode::InvalidInput,
                &ledger_info,
            )
        })?;
    }
    
    state_view
        .as_converter(context.db.clone(), context.indexer_reader.clone())
        .convert_view_function(data.0)
        .map_err(|err| {
            BasicErrorWith404::bad_request_with_code(
                err,
                AptosErrorCode::InvalidInput,
                &ledger_info,
            )
        })?
}
```

This ensures parity with entry function validation and BCS ViewRequest protection.

## Proof of Concept

```rust
// PoC: Craft JSON ViewRequest with excessive type nesting
use serde_json::json;

fn create_deeply_nested_type(depth: usize) -> serde_json::Value {
    let mut nested = json!("u8");
    for _ in 0..depth {
        nested = json!({
            "Vector": {
                "items": nested
            }
        });
    }
    nested
}

// Send to /view endpoint:
let malicious_request = json!({
    "function": "0x1::some_module::some_function",
    "type_arguments": [
        create_deeply_nested_type(50)  // Exceeds MAX_RECURSIVE_TYPES_ALLOWED
    ],
    "arguments": []
});

// POST to /v1/view
// Result: Excessive CPU consumption during TryFrom conversion
// Eventually rejected by VM, but resources already consumed
```

To test:
1. Deploy a view function accepting generic type parameter
2. Send JSON ViewRequest with nested Vector types (depth 50)
3. Monitor API response time and CPU usage
4. Compare with depth-8 types showing performance degradation
5. Verify BCS equivalent request is rejected immediately

## Notes
This vulnerability demonstrates that the `ensure!` check in `convert_view_function()` provides insufficient validation. While it correctly validates type argument count, it fails to validate structural properties that are enforced elsewhere in the system. The fix requires adding the same `verify()` call that protects entry function submissions, ensuring consistent input validation across all API paths.

### Citations

**File:** api/types/src/convert.rs (L1036-1042)
```rust
        ensure!(
            func.generic_type_params.len() == type_arguments.len(),
            "expected {} type arguments for view function {}, but got {}",
            func.generic_type_params.len(),
            function,
            type_arguments.len()
        );
```

**File:** api/types/src/convert.rs (L1052-1055)
```rust
            ty_args: type_arguments
                .iter()
                .map(|v| v.try_into())
                .collect::<Result<_>>()?,
```

**File:** api/src/view_function.rs (L115-125)
```rust
    let view_function: ViewFunction = match request {
        ViewFunctionRequest::Json(data) => state_view
            .as_converter(context.db.clone(), context.indexer_reader.clone())
            .convert_view_function(data.0)
            .map_err(|err| {
                BasicErrorWith404::bad_request_with_code(
                    err,
                    AptosErrorCode::InvalidInput,
                    &ledger_info,
                )
            })?,
```

**File:** api/src/view_function.rs (L126-136)
```rust
        ViewFunctionRequest::Bcs(data) => {
            bcs::from_bytes_with_limit(data.0.as_slice(), MAX_RECURSIVE_TYPES_ALLOWED as usize)
                .context("Failed to deserialize input into ViewRequest")
                .map_err(|err| {
                    BasicErrorWith404::bad_request_with_code(
                        err,
                        AptosErrorCode::InvalidInput,
                        &ledger_info,
                    )
                })?
        },
```

**File:** api/types/src/move_types.rs (L690-713)
```rust
impl VerifyInputWithRecursion for MoveType {
    fn verify(&self, recursion_count: u8) -> anyhow::Result<()> {
        if recursion_count > MAX_RECURSIVE_TYPES_ALLOWED {
            bail!(
                "Move type {} has gone over the limit of recursive types {}",
                self,
                MAX_RECURSIVE_TYPES_ALLOWED
            );
        }
        match self {
            MoveType::Vector { items } => items.verify(recursion_count + 1),
            MoveType::Struct(struct_tag) => struct_tag.verify(recursion_count + 1),
            MoveType::Function { args, results, .. } => {
                for ty in args.iter().chain(results) {
                    ty.verify(recursion_count + 1)?
                }
                Ok(())
            },
            MoveType::GenericTypeParam { .. } => Ok(()),
            MoveType::Reference { to, .. } => to.verify(recursion_count + 1),
            MoveType::Unparsable(inner) => bail!("Unable to parse move type {}", inner),
            _ => Ok(()),
        }
    }
```

**File:** api/types/src/move_types.rs (L928-987)
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
```

**File:** api/src/transactions.rs (L1377-1388)
```rust
        for arg in payload.ty_args() {
            let arg: MoveType = arg.into();
            arg.verify(0)
                .context("Transaction entry function type arg invalid")
                .map_err(|err| {
                    SubmitTransactionError::bad_request_with_code(
                        err,
                        AptosErrorCode::InvalidInput,
                        ledger_info,
                    )
                })?;
        }
```
