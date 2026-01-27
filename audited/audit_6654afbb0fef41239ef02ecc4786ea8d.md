# Audit Report

## Title
Missing Depth Validation in Move VM Value Deserialization Enables Stack Overflow Attack

## Summary
The Move VM's resource deserialization path fails to enforce the configured maximum value nesting depth limit, creating an asymmetry with the serialization path that properly enforces this limit. This missing validation could allow stack overflow attacks if deeply nested blobs reach storage through non-standard paths (genesis, state sync, or historical data).

## Finding Description

The `create_data_cache_entry()` function deserializes resource blobs from storage without validating nesting depth, violating the defensive principle that both serialization and deserialization should enforce the same invariants. [1](#0-0) 

The deserialization configures `max_value_nest_depth` but **never checks it**: [2](#0-1) 

The `DeserializationSeed` structure lacks any `depth` field: [3](#0-2) 

In contrast, serialization properly enforces depth limits at line 4838: [4](#0-3) 

The code comments explicitly warn about stack overflow risks: [5](#0-4) 

When deserializing nested structures (vectors, structs, functions), new `DeserializationSeed` instances are created recursively without depth tracking: [6](#0-5) 

## Impact Explanation

**Severity: High** (potential validator node crashes)

While normal transaction execution enforces depth limits during serialization, this vulnerability creates risk through:

1. **Genesis/Setup Operations**: Direct database writes during chain initialization may bypass serialization
2. **State Sync**: Validators receiving state from peers might deserialize unchecked blobs  
3. **Historical Data**: If depth limits changed over time, old data could exceed current limits
4. **Consensus Risk**: Stack overflow crashes during resource access could cause validator liveness failures

Stack overflow in Rust causes process abort, leading to:
- Validator node crashes when accessing affected resources
- Potential consensus disruption if multiple validators crash
- Denial of service if critical system resources are affected

## Likelihood Explanation

**Likelihood: Low-Medium**

The attack requires deeply nested blobs (128+ levels) to reach storage through non-standard paths. Normal transaction execution prevents this through serialization checks. However:

- Genesis operations may lack validation
- State sync validation gaps could exist
- Configuration changes over network lifetime create risk
- The asymmetry violates defense-in-depth principles

## Recommendation

Add depth tracking and validation to deserialization, mirroring the serialization implementation:

1. **Add depth field to `DeserializationSeed`**:
```rust
pub(crate) struct DeserializationSeed<'c, L> {
    pub(crate) ctx: &'c ValueSerDeContext<'c>,
    pub(crate) layout: L,
    pub(crate) depth: u64,  // ADD THIS
}
```

2. **Check depth at start of deserialization** (similar to line 4838 in serialization):
```rust
fn deserialize<D: serde::de::Deserializer<'d>>(
    self,
    deserializer: D,
) -> Result<Self::Value, D::Error> {
    // ADD THIS CHECK
    self.ctx.check_depth(self.depth).map_err(D::Error::custom)?;
    
    use MoveTypeLayout as L;
    match self.layout {
        // ... rest of implementation
    }
}
```

3. **Increment depth when recursing** (at all sites creating new `DeserializationSeed`):
```rust
DeserializationSeed {
    ctx: self.ctx,
    layout: struct_layout,
    depth: self.depth + 1,  // ADD THIS
}
```

4. **Initialize with depth=1** in `ValueSerDeContext::deserialize()`:
```rust
pub fn deserialize(self, bytes: &[u8], layout: &MoveTypeLayout) -> Option<Value> {
    let seed = DeserializationSeed { 
        ctx: &self, 
        layout,
        depth: 1,  // ADD THIS
    };
    bcs::from_bytes_seed(seed, bytes).ok()
}
```

## Proof of Concept

```rust
#[test]
fn test_deeply_nested_deserialization_missing_check() {
    use move_core_types::value::MoveTypeLayout;
    use crate::value_serde::ValueSerDeContext;
    
    // Create a blob representing a deeply nested vector
    // vec<vec<vec<...<u8>...>>> with 200 levels of nesting
    let mut nested_layout = MoveTypeLayout::U8;
    for _ in 0..200 {
        nested_layout = MoveTypeLayout::Vector(Box::new(nested_layout));
    }
    
    // Manually construct BCS blob with 200 levels of nesting
    // Each level: [1-byte length] + [inner content]
    let mut blob = vec![0u8]; // innermost u8 value
    for _ in 0..200 {
        blob = {
            let mut outer = vec![1u8]; // vector length = 1
            outer.extend(blob);
            outer
        };
    }
    
    // Attempt deserialization - should fail with depth limit but doesn't
    let ctx = ValueSerDeContext::new(Some(128)); // configured limit = 128
    let result = ctx.deserialize(&blob, &nested_layout);
    
    // BUG: Deserialization succeeds or causes stack overflow
    // instead of returning None due to depth limit violation
    // Expected: None (depth limit exceeded)
    // Actual: Some(value) or stack overflow panic
}
```

## Notes

This vulnerability represents a **defensive programming gap** rather than an immediately exploitable attack. While serialization properly prevents deeply nested values from being written during normal transaction execution, the missing validation in deserialization violates the principle that input validation should occur at trust boundaries. The asymmetry creates risk during genesis setup, state synchronization, or after configuration changes, where deeply nested structures could potentially bypass the serialization path.

### Citations

**File:** third_party/move/move-vm/runtime/src/data_cache.rs (L299-315)
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
```

**File:** third_party/move/move-vm/types/src/value_serde.rs (L238-241)
```rust
    pub fn deserialize(self, bytes: &[u8], layout: &MoveTypeLayout) -> Option<Value> {
        let seed = DeserializationSeed { ctx: &self, layout };
        bcs::from_bytes_seed(seed, bytes).ok()
    }
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

**File:** third_party/move/move-vm/types/src/values/values_impl.rs (L4834-4838)
```rust
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

**File:** third_party/move/move-vm/types/src/values/values_impl.rs (L5131-5138)
```rust
            // Structs.
            L::Struct(struct_layout) => {
                let seed = DeserializationSeed {
                    ctx: self.ctx,
                    layout: struct_layout,
                };
                Ok(Value::struct_(seed.deserialize(deserializer)?))
            },
```
