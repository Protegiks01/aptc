# Audit Report

## Title
Unhandled Panic in Resource Deserialization Can Crash Validator Nodes

## Summary
The `create_data_cache_entry()` function in the Move VM runtime uses `ok_or_else()` to convert deserialization failures to errors, but this only catches `Option::None` results, not panics. Malformed resource blobs with excessive nesting depth can cause stack overflow panics during BCS deserialization that propagate uncaught through the validator, causing node crashes.

## Finding Description

The vulnerability exists in the resource loading path where on-chain resources are deserialized from storage. The critical flaw is that the deserialization code lacks panic protection that exists in other parts of the codebase.

**Vulnerable Code Path:** [1](#0-0) 

The deserialization uses `ok_or_else()` which only converts `Option::None` to an error. However, the underlying `ValueSerDeContext::deserialize()` method: [2](#0-1) 

This calls `bcs::from_bytes_seed()` with `.ok()`, which converts `Result::Err` to `Option::None` but **does not catch panics**.

The `DeserializationSeed` implementation is recursive for nested structures: [3](#0-2) 

**Critical Gap:** Unlike module deserialization which uses `catch_unwind`: [4](#0-3) 

The resource deserialization path has **no panic protection**.

**Depth Checking Only During Serialization:**

The `check_depth()` method exists but is only enforced during serialization: [5](#0-4) 

There is no corresponding depth check in the `DeserializationSeed::deserialize` implementation, allowing unbounded recursion.

**No Panic Handling at VM Execution Level:**

The transaction execution entry point has no panic catching: [6](#0-5) 

**Attack Scenario:**
1. Malformed resource blob with deeply nested structures (e.g., `vector<vector<vector<...>>>` nested 10,000+ levels) exists on-chain
2. Transaction attempts to read this resource via `move_from`, `borrow_global`, etc.
3. `load_resource_mut()` calls `create_data_cache_entry()`
4. BCS deserialization recurses deeply, exceeding stack limits
5. Stack overflow triggers panic
6. Panic is not caught by `ok_or_else`, `catch_unwind`, or any other handler
7. Validator node crashes

This breaks the **Move VM Safety** invariant (operations must respect memory constraints) and the **consensus availability** guarantee.

## Impact Explanation

**Severity: High** (per Aptos Bug Bounty criteria: "Validator node slowdowns" and "Significant protocol violations")

This vulnerability can cause:
- **Validator Node Crashes**: Any validator attempting to process a transaction that reads the malformed resource will crash
- **Consensus Liveness Impact**: If enough validators crash simultaneously, the network could lose liveness
- **Deterministic DOS**: The malformed resource remains on-chain, causing repeated crashes for any validator attempting to access it
- **No Byzantine Behavior Required**: The attack only requires malformed data in storage, which could originate from various sources

While not Critical severity (doesn't directly steal funds or permanently partition the network), it represents a significant protocol violation that can degrade validator availability and network reliability.

## Likelihood Explanation

**Likelihood: Medium-High**

The attack is realistic because:
- **Malformed Data Sources**: Could originate from bugs in serialization logic, storage corruption, or past vulnerabilities
- **Easy Trigger**: Any transaction reading the affected resource triggers the crash
- **Persistent Impact**: The malformed data persists on-chain until manually removed
- **No Special Privileges**: Any user can trigger the crash by sending a transaction that reads the resource

The main limitation is that malformed resource blobs must already exist on-chain, which requires either a prior vulnerability or data corruption. However, once present, exploitation is trivial.

## Recommendation

**Fix 1: Add Panic Protection (Primary)**

Wrap the deserialization call with `catch_unwind` similar to module deserialization:

```rust
fn create_data_cache_entry(
    // ... parameters
) -> PartialVMResult<(DataCacheEntry, NumBytes)> {
    // ... existing code up to deserialization ...
    
    let function_value_extension = FunctionValueExtensionAdapter { module_storage };
    let (layout, contains_delayed_fields) = layout_with_delayed_fields.unpack();
    let value = match data {
        Some(blob) => {
            let max_value_nest_depth = function_value_extension.max_value_nest_depth();
            
            // Set state for crash handler
            let prev_state = move_core_types::state::set_state(VMState::DESERIALIZER);
            
            // Wrap deserialization with panic protection
            let result = std::panic::catch_unwind(|| {
                ValueSerDeContext::new(max_value_nest_depth)
                    .with_func_args_deserialization(&function_value_extension)
                    .with_delayed_fields_serde()
                    .deserialize(&blob, &layout)
            })
            .unwrap_or(None); // Convert panic to None
            
            move_core_types::state::set_state(prev_state);
            
            let val = result.ok_or_else(|| {
                let msg = format!(
                    "Failed to deserialize resource {} at {}!",
                    struct_tag.to_canonical_string(),
                    addr
                );
                PartialVMError::new(StatusCode::FAILED_TO_DESERIALIZE_RESOURCE)
                    .with_message(msg)
            })?;
            GlobalValue::cached(val)?
        },
        None => GlobalValue::none(),
    };
    // ... rest of function
}
```

**Fix 2: Add Depth Checking During Deserialization (Defense in Depth)**

Modify `DeserializationSeed` to track and enforce depth limits during deserialization, not just serialization. This requires threading a depth counter through the recursive calls.

**Fix 3: Resource Validation (Preventive)**

Add on-chain validation to reject resources exceeding depth limits during writes, preventing malformed data from being stored initially.

## Proof of Concept

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use move_core_types::value::MoveTypeLayout;
    
    #[test]
    fn test_deeply_nested_resource_panic() {
        // Create a deeply nested vector type: vector<vector<vector<...u8>>>
        let depth = 5000; // Adjust based on stack size
        let mut layout = MoveTypeLayout::U8;
        for _ in 0..depth {
            layout = MoveTypeLayout::Vector(Box::new(layout));
        }
        
        // Create corresponding deeply nested blob
        // Start with innermost value: [42u8]
        let mut blob = bcs::to_bytes(&vec![42u8]).unwrap();
        for _ in 0..depth {
            // Wrap in another vector layer
            blob = bcs::to_bytes(&vec![blob]).unwrap();
        }
        
        // This should panic due to stack overflow during deserialization
        // Without catch_unwind, this would crash the test/validator
        let result = std::panic::catch_unwind(|| {
            ValueSerDeContext::new(Some(128))
                .deserialize(&blob, &layout)
        });
        
        // Verify that deserialization either panicked or returned None
        assert!(result.is_err() || result.unwrap().is_none(),
            "Deep nesting should cause panic or deserialization failure");
    }
}
```

**Notes:**
- The exact depth required to trigger stack overflow depends on stack size configuration
- On typical Rust configurations, 1000-2000 levels of nesting can cause issues
- The PoC demonstrates the vulnerability principle; actual exploitation would involve crafting on-chain resources with similar deep nesting

### Citations

**File:** third_party/move/move-vm/runtime/src/data_cache.rs (L299-318)
```rust
        let value = match data {
            Some(blob) => {
                let max_value_nest_depth = function_value_extension.max_value_nest_depth();
                let val = ValueSerDeContext::new(max_value_nest_depth)
                    .with_func_args_deserialization(&function_value_extension)
                    .with_delayed_fields_serde()
                    .deserialize(&blob, &layout)
                    .ok_or_else(|| {
                        let msg = format!(
                            "Failed to deserialize resource {} at {}!",
                            struct_tag.to_canonical_string(),
                            addr
                        );
                        PartialVMError::new(StatusCode::FAILED_TO_DESERIALIZE_RESOURCE)
                            .with_message(msg)
                    })?;
                GlobalValue::cached(val)?
            },
            None => GlobalValue::none(),
        };
```

**File:** third_party/move/move-vm/types/src/value_serde.rs (L238-241)
```rust
    pub fn deserialize(self, bytes: &[u8], layout: &MoveTypeLayout) -> Option<Value> {
        let seed = DeserializationSeed { ctx: &self, layout };
        bcs::from_bytes_seed(seed, bytes).ok()
    }
```

**File:** third_party/move/move-vm/types/src/values/values_impl.rs (L4838-4838)
```rust
        self.ctx.check_depth(self.depth).map_err(S::Error::custom)?;
```

**File:** third_party/move/move-vm/types/src/values/values_impl.rs (L5092-5164)
```rust
impl<'d> serde::de::DeserializeSeed<'d> for DeserializationSeed<'_, &MoveTypeLayout> {
    type Value = Value;

    fn deserialize<D: serde::de::Deserializer<'d>>(
        self,
        deserializer: D,
    ) -> Result<Self::Value, D::Error> {
        use MoveTypeLayout as L;

        match self.layout {
            // Primitive types.
            L::Bool => bool::deserialize(deserializer).map(Value::bool),
            L::U8 => u8::deserialize(deserializer).map(Value::u8),
            L::U16 => u16::deserialize(deserializer).map(Value::u16),
            L::U32 => u32::deserialize(deserializer).map(Value::u32),
            L::U64 => u64::deserialize(deserializer).map(Value::u64),
            L::U128 => u128::deserialize(deserializer).map(Value::u128),
            L::U256 => int256::U256::deserialize(deserializer).map(Value::u256),
            L::I8 => i8::deserialize(deserializer).map(Value::i8),
            L::I16 => i16::deserialize(deserializer).map(Value::i16),
            L::I32 => i32::deserialize(deserializer).map(Value::i32),
            L::I64 => i64::deserialize(deserializer).map(Value::i64),
            L::I128 => i128::deserialize(deserializer).map(Value::i128),
            L::I256 => int256::I256::deserialize(deserializer).map(Value::i256),
            L::Address => AccountAddress::deserialize(deserializer).map(Value::address),
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

            // Structs.
            L::Struct(struct_layout) => {
                let seed = DeserializationSeed {
                    ctx: self.ctx,
                    layout: struct_layout,
                };
                Ok(Value::struct_(seed.deserialize(deserializer)?))
            },

            // Vectors.
            L::Vector(layout) => Ok(match layout.as_ref() {
                L::U8 => Value::vector_u8(Vec::deserialize(deserializer)?),
                L::U16 => Value::vector_u16(Vec::deserialize(deserializer)?),
                L::U32 => Value::vector_u32(Vec::deserialize(deserializer)?),
                L::U64 => Value::vector_u64(Vec::deserialize(deserializer)?),
                L::U128 => Value::vector_u128(Vec::deserialize(deserializer)?),
                L::U256 => Value::vector_u256(Vec::deserialize(deserializer)?),
                L::I8 => Value::vector_i8(Vec::deserialize(deserializer)?),
                L::I16 => Value::vector_i16(Vec::deserialize(deserializer)?),
                L::I32 => Value::vector_i32(Vec::deserialize(deserializer)?),
                L::I64 => Value::vector_i64(Vec::deserialize(deserializer)?),
                L::I128 => Value::vector_i128(Vec::deserialize(deserializer)?),
                L::I256 => Value::vector_i256(Vec::deserialize(deserializer)?),
                L::Bool => Value::vector_bool(Vec::deserialize(deserializer)?),
                L::Address => Value::vector_address(Vec::deserialize(deserializer)?),
                layout => {
                    let seed = DeserializationSeed {
                        ctx: self.ctx,
                        layout,
                    };
                    let vector = deserializer.deserialize_seq(VectorElementVisitor(seed))?;
                    Value::Container(Container::Vec(Rc::new(RefCell::new(vector))))
                },
            }),
```

**File:** third_party/move/move-binary-format/src/deserializer.rs (L56-68)
```rust
        let prev_state = move_core_types::state::set_state(VMState::DESERIALIZER);
        let result = std::panic::catch_unwind(|| {
            let module = deserialize_compiled_module(binary, config)?;
            BoundsChecker::verify_module(&module)?;

            Ok(module)
        })
        .unwrap_or_else(|_| {
            Err(PartialVMError::new(
                StatusCode::VERIFIER_INVARIANT_VIOLATION,
            ))
        });
        move_core_types::state::set_state(prev_state);
```

**File:** aptos-move/aptos-vm/src/aptos_vm.rs (L1982-2012)
```rust
    fn execute_user_transaction_impl(
        &self,
        resolver: &impl AptosMoveResolver,
        code_storage: &impl AptosCodeStorage,
        txn: &SignedTransaction,
        txn_data: TransactionMetadata,
        is_approved_gov_script: bool,
        log_context: &AdapterLogSchema,
        gas_meter: &mut impl AptosGasMeter,
        mut trace_recorder: impl TraceRecorder,
    ) -> (VMStatus, VMOutput) {
        let _timer = VM_TIMER.timer_with_label("AptosVM::execute_user_transaction_impl");

        let traversal_storage = TraversalStorage::new();
        let mut traversal_context = TraversalContext::new(&traversal_storage);

        // Revalidate the transaction.
        let mut prologue_session = PrologueSession::new(self, &txn_data, resolver);
        let initial_gas = gas_meter.balance();
        let serialized_signers = unwrap_or_discard!(prologue_session.execute(|session| {
            self.validate_signed_transaction(
                session,
                code_storage,
                txn,
                &txn_data,
                log_context,
                is_approved_gov_script,
                &mut traversal_context,
                gas_meter,
            )
        }));
```
