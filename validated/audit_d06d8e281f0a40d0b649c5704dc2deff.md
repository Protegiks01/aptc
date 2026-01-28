# Audit Report

## Title
Verifier-Executor Depth Limit Inconsistency in Constant Deserialization

## Summary
There is a mismatch between the maximum allowed nesting depth for constants during bytecode verification versus VM execution. The bytecode verifier allows type signatures up to depth 256 and uses `MoveValue::simple_deserialize()` without explicit depth checking, while the VM executor enforces a depth limit of 128. This allows modules with deeply nested constants (depth 129-256) to pass verification but fail deterministically at execution time, violating the invariant that verified code should be executable.

## Finding Description

The vulnerability stems from inconsistent depth validation across two critical code paths:

**Verification Path:**

During module publishing, the bytecode verifier validates constants but does not enforce value depth limits: [1](#0-0) 

The verifier calls `Constant::deserialize_constant()` which uses `MoveValue::simple_deserialize()`: [2](#0-1) 

This function performs only BCS deserialization without depth checking: [3](#0-2) 

Type signatures are limited to depth 256: [4](#0-3) 

**Execution Path:**

When the `LdConst` instruction loads a constant during execution: [5](#0-4) 

It calls `Value::deserialize_constant()` which enforces a depth limit of 128: [6](#0-5) 

The depth limit constant is set to 128: [7](#0-6) 

When depth is exceeded, the check returns an error: [8](#0-7) 

**Attack Scenario:**
1. Attacker creates a module with a constant of type `vector<vector<...vector<u8>...>>` with nesting depth between 129-256
2. Submits transaction to publish the module
3. Verifier accepts it (type depth ≤ 256, no value depth check during verification)
4. Module gets published successfully
5. Any transaction attempting to execute code that loads this constant fails with `VERIFIER_INVARIANT_VIOLATION`
6. The module becomes permanently unexecutable despite passing verification

## Impact Explanation

This qualifies as **Medium Severity** under the Aptos bug bounty program as it creates "State inconsistencies requiring manual intervention."

**Specific Impacts:**
- **Invariant Violation**: Breaks the fundamental assumption that bytecode-verified modules are executable
- **Resource Waste**: Attackers can publish modules that consume storage but are unusable
- **Deterministic DoS**: Creates permanently broken code that passed verification
- **Gas Inefficiency**: Users waste gas attempting to call functions that will always fail

**Not Critical Because:**
- All validators behave identically (deterministic failure, no consensus break)
- No fund loss or theft occurs
- Limited to DoS of specific modules, not network-wide impact

## Likelihood Explanation

**High Likelihood** due to:
- Any user can publish modules (no special privileges required)
- Attack is straightforward - just requires crafting deeply nested type signatures
- Constant size limit (65535 bytes) easily accommodates 200+ nesting levels
- Gap between limits is significant (128 vs 256)

## Recommendation

Add depth validation during constant verification to match execution limits. Modify the verifier to use the same depth limit as execution:

In `third_party/move/move-bytecode-verifier/src/constants.rs`, the `verify_constant_data()` function should deserialize constants with the same depth limit as execution (128) instead of using `MoveValue::simple_deserialize()` which has no depth checking. 

The fix should ensure that `Constant::deserialize_constant()` uses `ValueSerDeContext::new(Some(DEFAULT_MAX_VM_VALUE_NESTED_DEPTH))` for deserialization, consistent with the execution path.

## Proof of Concept

Create a Move module with a constant that has vector nesting depth of 150 (between 128 and 256):
```
const DEEP_NESTED: vector<vector<vector<...(150 levels)...vector<u8>...>>> = ...;
```

The module will pass bytecode verification but any function attempting to load this constant will fail with `VERIFIER_INVARIANT_VIOLATION` at runtime.

## Notes

The vulnerability is confirmed by examining the actual implementation differences between verification and execution paths. The verifier's comment in `values_impl.rs` explicitly states "For constants, layout depth is bounded" as an invariant, but the verifier fails to enforce this bound during constant validation.

### Citations

**File:** third_party/move/move-bytecode-verifier/src/constants.rs (L55-63)
```rust
fn verify_constant_data(idx: usize, constant: &Constant) -> PartialVMResult<()> {
    match constant.deserialize_constant() {
        Some(_) => Ok(()),
        None => Err(verification_error(
            StatusCode::MALFORMED_CONSTANT_DATA,
            IndexKind::ConstantPool,
            idx as TableIndex,
        )),
    }
```

**File:** third_party/move/move-binary-format/src/constant.rs (L71-74)
```rust
    pub fn deserialize_constant(&self) -> Option<MoveValue> {
        let ty = sig_to_ty(&self.type_)?;
        MoveValue::simple_deserialize(&self.data, &ty).ok()
    }
```

**File:** third_party/move/move-core/types/src/value.rs (L294-296)
```rust
    pub fn simple_deserialize(blob: &[u8], ty: &MoveTypeLayout) -> AResult<Self> {
        Ok(bcs::from_bytes_seed(ty, blob)?)
    }
```

**File:** third_party/move/move-binary-format/src/file_format_common.rs (L88-88)
```rust
pub const SIGNATURE_TOKEN_DEPTH_MAX: usize = 256;
```

**File:** third_party/move/move-vm/runtime/src/interpreter.rs (L2138-2156)
```rust
                    Instruction::LdConst(idx) => {
                        let constant = self.constant_at(*idx);

                        gas_meter.charge_create_ty(NumTypeNodes::new(
                            constant.type_.num_nodes() as u64,
                        ))?;
                        gas_meter.charge_ld_const(NumBytes::new(constant.data.len() as u64))?;

                        let val = Value::deserialize_constant(constant).ok_or_else(|| {
                            PartialVMError::new(StatusCode::VERIFIER_INVARIANT_VIOLATION)
                                .with_message(
                                    "Verifier failed to verify the deserialization of constants"
                                        .to_owned(),
                                )
                        })?;

                        gas_meter.charge_ld_const_after_deserialization(&val)?;
                        interpreter.operand_stack.push(val)?;
                    },
```

**File:** third_party/move/move-vm/types/src/values/values_impl.rs (L50-57)
```rust
/// Values can be recursive, and so it is important that we do not use recursive algorithms over
/// deeply nested values as it can cause stack overflow. Since it is not always possible to avoid
/// recursion, we opt for a reasonable limit on VM value depth. It is defined in Move VM config,
/// but since it is difficult to propagate config context everywhere, we use this constant.
///
/// IMPORTANT: When changing this constant, make sure it is in-sync with one in VM config (it is
/// used there now).
pub const DEFAULT_MAX_VM_VALUE_NESTED_DEPTH: u64 = 128;
```

**File:** third_party/move/move-vm/types/src/values/values_impl.rs (L5442-5449)
```rust
    pub fn deserialize_constant(constant: &Constant) -> Option<Value> {
        let layout = Self::constant_sig_token_to_layout(&constant.type_)?;
        // INVARIANT:
        //   For constants, layout depth is bounded and cannot contain function values. Hence,
        //   serialization depth is bounded. We still enable depth checks as a precaution.
        ValueSerDeContext::new(Some(DEFAULT_MAX_VM_VALUE_NESTED_DEPTH))
            .deserialize(&constant.data, &layout)
    }
```

**File:** third_party/move/move-vm/types/src/value_serde.rs (L149-157)
```rust
    pub(crate) fn check_depth(&self, depth: u64) -> PartialVMResult<()> {
        if self
            .max_value_nested_depth
            .is_some_and(|max_depth| depth > max_depth)
        {
            return Err(PartialVMError::new(StatusCode::VM_MAX_VALUE_DEPTH_REACHED));
        }
        Ok(())
    }
```
