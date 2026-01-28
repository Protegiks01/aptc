# Audit Report

## Title
Missing Depth Validation During BCS Deserialization Causes Asymmetric Checks and Potential Consensus Issues

## Summary
The Move VM's value deserialization path fails to enforce depth limits even when `enable_depth_checks` is configured, creating an asymmetry with serialization which does enforce these limits. This allows deeply nested structures to bypass validation during deserialization, potentially causing state inconsistencies and consensus divergence between nodes with different configurations.

## Finding Description

The vulnerability exists in the implementation of BCS value deserialization for Move VM values. While serialization properly enforces depth limits, the deserialization path completely omits this validation.

**Serialization (CORRECT Implementation):**

The `SerializationReadyValue` struct includes an explicit `depth` field for tracking nesting depth: [1](#0-0) 

The serialization implementation calls `check_depth()` at the beginning to validate depth limits: [2](#0-1) 

When recursing into nested structures like vectors, depth is properly incremented: [3](#0-2) 

**Deserialization (VULNERABLE Implementation):**

The `DeserializationSeed` struct has no `depth` field: [4](#0-3) 

The `deserialize` implementation never calls `check_depth()` and proceeds recursively without depth validation: [5](#0-4) 

**Attack Scenario:**

1. **Configuration-Based Attack**: When `enable_depth_checks` is controlled by the ENABLE_FUNCTION_VALUES feature flag: [6](#0-5) 

2. **Value Creation Without Checks**: When depth checks are disabled, the `max_value_nest_depth()` method returns `None`: [7](#0-6) 

3. **Bypass via VecPushBack**: The `VecPushBack` instruction does not perform depth checking, unlike `VecPack`: [8](#0-7) 

Compare with `VecPack` which does check depth: [9](#0-8) 

4. **Depth Check Logic**: When `max_depth` is `None`, checks always pass: [10](#0-9) 

5. **Exploitation**: During network transitions from `enable_depth_checks = false` to `true`, deeply nested values (depth > 128) can be created and stored. When later deserialized with strict checks enabled, deserialization succeeds without validation. However, subsequent serialization attempts fail, returning `None`: [11](#0-10) 

## Impact Explanation

**Medium Severity** - This qualifies as "State inconsistencies requiring manual intervention" under the Aptos bug bounty criteria:

1. **State Consistency Violation**: Values that can be deserialized but not serialized create an asymmetric state where operations succeed in one direction but fail in the other. This violates fundamental state consistency invariants.

2. **Configuration Transition Risk**: During feature flag transitions (specifically ENABLE_FUNCTION_VALUES), nodes may exhibit different behaviors when processing the same deeply nested values, depending on when they loaded the values and what operations they perform on them.

3. **Operational Risk**: Once deeply nested values enter state during periods with relaxed checks, they persist and require network intervention to resolve inconsistencies.

4. **Resource Exhaustion Potential**: Subsequent recursive operations on deserialized deeply nested values (like `copy_value`, `equals`, `compare`) enforce depth limits and could fail unexpectedly, as these operations do check depth: [12](#0-11) 

## Likelihood Explanation

**Medium Likelihood**:

1. **Feature Flag Transitions**: The vulnerability manifests during legitimate network operations when `enable_depth_checks` changes state. The production configuration ties this to ENABLE_FUNCTION_VALUES: [13](#0-12) 

2. **No Runtime Protection**: Unlike `VecPack`, the `VecPushBack` operation has no depth checking, allowing deeply nested values to be constructed incrementally without validation.

3. **State Persistence**: Values stored in tables/resources during periods with relaxed depth checks persist indefinitely and can trigger the asymmetry when later accessed with strict checks enabled.

4. **Natural Occurrence**: This is not purely theoretical - it can naturally occur during network upgrades and configuration management without malicious intent.

## Recommendation

Add depth tracking and validation to the deserialization path:

1. Add a `depth` field to `DeserializationSeed` struct
2. Call `ctx.check_depth(depth)` at the start of the `deserialize` implementation
3. Increment depth when recursing into nested structures (vectors, structs, variants)
4. Consider adding depth checks to `VecPushBack` instruction for consistency with `VecPack`

The fix should mirror the serialization implementation's depth tracking approach.

## Proof of Concept

The asymmetry can be demonstrated by:
1. Creating a deeply nested value (depth > 128) when `enable_depth_checks = false`
2. Serializing it successfully (depth check passes with `None`)
3. Storing it in a table or resource
4. Enabling `enable_depth_checks = true`
5. Deserializing the value successfully (no depth check)
6. Attempting to re-serialize the value (fails due to depth check, returns `None`)

This demonstrates the core asymmetry where deserialization succeeds but serialization fails for the same value under the same configuration, violating state consistency invariants.

## Notes

The vulnerability is confirmed through code analysis showing:
- Serialization enforces depth limits via `check_depth()` calls
- Deserialization omits depth validation entirely  
- Configuration transitions via feature flags can trigger the vulnerability
- The asymmetry creates state consistency issues during network upgrades

The impact is limited to Medium severity because it requires specific configuration transitions and does not directly enable fund theft or complete network halts, but it does create state inconsistencies requiring operational intervention.

### Citations

**File:** third_party/move/move-vm/types/src/values/values_impl.rs (L580-585)
```rust
    #[inline(always)]
    fn copy_value(&self, depth: u64, max_depth: Option<u64>) -> PartialVMResult<Self> {
        use Value::*;

        check_depth(depth, max_depth)?;
        Ok(match self {
```

**File:** third_party/move/move-vm/types/src/values/values_impl.rs (L4818-4826)
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
```

**File:** third_party/move/move-vm/types/src/values/values_impl.rs (L4834-4838)
```rust
impl serde::Serialize for SerializationReadyValue<'_, '_, '_, MoveTypeLayout, Value> {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        use MoveTypeLayout as L;

        self.ctx.check_depth(self.depth).map_err(S::Error::custom)?;
```

**File:** third_party/move/move-vm/types/src/values/values_impl.rs (L4898-4909)
```rust
                    (_, Container::Vec(r)) => {
                        let v = r.borrow();
                        let mut t = serializer.serialize_seq(Some(v.len()))?;
                        for value in v.iter() {
                            t.serialize_element(&SerializationReadyValue {
                                ctx: self.ctx,
                                layout,
                                value,
                                depth: self.depth + 1,
                            })?;
                        }
                        t.end()
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

**File:** aptos-move/aptos-vm-environment/src/prod_configs.rs (L221-227)
```rust
    // Value runtime depth checks have been introduced together with function values and are only
    // enabled when the function values are enabled. Previously, checks were performed over types
    // to bound the value depth (checking the size of a packed struct type bounds the value), but
    // this no longer applies once function values are enabled. With function values, types can be
    // shallow while the value can be deeply nested, thanks to captured arguments not visible in a
    // type. Hence, depth checks have been adjusted to operate on values.
    let enable_depth_checks = features.is_enabled(FeatureFlag::ENABLE_FUNCTION_VALUES);
```

**File:** aptos-move/aptos-native-interface/src/context.rs (L174-186)
```rust
    pub fn max_value_nest_depth(&self) -> Option<u64> {
        self.module_storage()
            .runtime_environment()
            .vm_config()
            .enable_depth_checks
            .then(|| {
                self.module_storage()
                    .runtime_environment()
                    .vm_config()
                    .max_value_nest_depth
            })
            .flatten()
    }
```

**File:** third_party/move/move-vm/runtime/src/interpreter.rs (L2952-2964)
```rust
                    Instruction::VecPack(si, num) => {
                        let (ty, ty_count) = frame_cache.get_signature_index_type(*si, self)?;
                        gas_meter.charge_create_ty(ty_count)?;
                        interpreter.ty_depth_checker.check_depth_of_type(
                            gas_meter,
                            traversal_context,
                            ty,
                        )?;
                        gas_meter
                            .charge_vec_pack(interpreter.operand_stack.last_n(*num as usize)?)?;
                        let elements = interpreter.operand_stack.popn(*num as u16)?;
                        let value = Vector::pack(ty, elements)?;
                        interpreter.operand_stack.push(value)?;
```

**File:** third_party/move/move-vm/runtime/src/interpreter.rs (L2992-2999)
```rust
                    Instruction::VecPushBack(si) => {
                        let elem = interpreter.operand_stack.pop()?;
                        let vec_ref = interpreter.operand_stack.pop_as::<VectorRef>()?;
                        let (_, ty_count) = frame_cache.get_signature_index_type(*si, self)?;
                        gas_meter.charge_create_ty(ty_count)?;
                        gas_meter.charge_vec_push_back(&elem)?;
                        vec_ref.push_back(elem)?;
                    },
```

**File:** third_party/move/move-vm/types/src/value_serde.rs (L188-218)
```rust
    pub fn serialize(
        self,
        value: &Value,
        layout: &MoveTypeLayout,
    ) -> PartialVMResult<Option<Vec<u8>>> {
        let value = SerializationReadyValue {
            ctx: &self,
            layout,
            value,
            depth: 1,
        };

        match bcs::to_bytes(&value).ok() {
            Some(bytes) => Ok(Some(bytes)),
            None => {
                // Check if the error is due to too many delayed fields. If so, to be compatible
                // with the older implementation return an error.
                if let Some(delayed_fields_extension) = self.delayed_fields_extension {
                    if delayed_fields_extension.delayed_fields_count.into_inner()
                        > DelayedFieldsExtension::MAX_DELAYED_FIELDS_PER_RESOURCE
                    {
                        return Err(PartialVMError::new(StatusCode::TOO_MANY_DELAYED_FIELDS)
                            .with_message(
                                "Too many Delayed fields in a single resource.".to_string(),
                            ));
                    }
                }
                Ok(None)
            },
        }
    }
```
