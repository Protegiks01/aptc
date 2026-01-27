# Audit Report

## Title
Memory Safety Violation via Unsafe UTF-8 Deserialization from Storage

## Summary
The Move VM's string native functions use `std::str::from_utf8_unchecked` assuming that all `String` values contain valid UTF-8 bytes. However, when resources containing `String` fields are loaded from storage, the BCS deserialization process does not validate UTF-8 encoding, creating a gap where invalid UTF-8 could trigger undefined behavior in Rust.

## Finding Description

The Move `String` type maintains a critical invariant: its `bytes` field must always contain valid UTF-8. This invariant is enforced at construction time: [1](#0-0) 

However, when a resource containing a `String` is loaded from storage, the deserialization path bypasses this validation. The deserialization occurs in: [2](#0-1) 

The `ValueSerDeContext::deserialize` method treats `String` as a generic struct and deserializes its `bytes: vector<u8>` field directly without UTF-8 validation: [3](#0-2) [4](#0-3) 

The native string functions rely on the unsafe assumption that bytes are valid UTF-8: [5](#0-4) [6](#0-5) [7](#0-6) 

**Attack Prerequisites:**
For this vulnerability to be exploited, invalid UTF-8 must first enter storage through:
1. A bytecode verification bypass allowing direct struct packing
2. A state synchronization vulnerability accepting corrupted data
3. Storage-layer corruption (hardware/software failure)
4. A VM memory corruption bug
5. Historical data from versions with weaker validation

## Impact Explanation

**Critical Severity** - This vulnerability violates multiple critical invariants:

1. **Memory Safety Violation**: `std::str::from_utf8_unchecked` with invalid UTF-8 is undefined behavior in Rust, potentially leading to memory corruption or arbitrary code execution.

2. **Consensus Divergence**: Different validators may handle undefined behavior differently based on compiler versions or optimizations, causing non-deterministic execution and consensus failure. This violates the **Deterministic Execution** invariant.

3. **Node Crashes**: String slicing operations can panic if indices don't fall on valid UTF-8 character boundaries, causing validator downtime.

4. **Incorrect Computation**: String operations like `find()` may return wrong results, leading to incorrect smart contract execution.

According to Rust documentation, undefined behavior invalidates all safety guarantees and can be exploited for arbitrary code execution.

## Likelihood Explanation

**Low-Medium Likelihood** - This is a conditional vulnerability requiring a separate bug to inject invalid UTF-8 into storage. However:

- **State sync vulnerabilities** have historically been found in blockchain systems
- **Storage corruption** can occur in production environments
- **Bytecode verifier bugs** have been discovered in various VM implementations
- The lack of defense-in-depth validation increases risk

The developers are aware of this risk, as evidenced by explicit validation in Move-level BCS deserialization: [8](#0-7) 

## Recommendation

Add UTF-8 validation when deserializing `String` types from storage. Implement validation in the `ValueSerDeContext::deserialize` path:

```rust
// In values_impl.rs, modify the Struct deserialization case:
L::Struct(struct_layout) => {
    let seed = DeserializationSeed {
        ctx: self.ctx,
        layout: struct_layout,
    };
    let s = seed.deserialize(deserializer)?;
    
    // Validate String structs after deserialization
    if is_string_struct(struct_layout) {
        if let Some(bytes_field) = get_string_bytes_field(&s) {
            std::str::from_utf8(bytes_field)
                .map_err(|_| D::Error::custom("Invalid UTF-8 in String from storage"))?;
        }
    }
    
    Ok(Value::struct_(s))
}
```

Alternatively, add a post-deserialization validation hook in `create_data_cache_entry` to validate all `String` fields recursively before caching the resource.

## Proof of Concept

**Note:** A complete PoC requires first finding a way to inject invalid UTF-8 into storage (e.g., through a bytecode verification bypass or state sync vulnerability). The following demonstrates the impact once invalid UTF-8 exists:

```rust
// Hypothetical scenario where invalid UTF-8 exists in storage
#[test]
fn test_invalid_utf8_from_storage() {
    // Assume resource bytes in storage contain a String with invalid UTF-8
    let corrupted_bytes = vec![
        0x01, // String struct with 1 field
        0x04, // vector<u8> length = 4
        0xFF, 0xFE, 0xFD, 0xFC, // Invalid UTF-8 bytes
    ];
    
    // Deserialize using ValueSerDeContext
    let layout = MoveTypeLayout::Struct(MoveStructLayout::Runtime(vec![
        MoveTypeLayout::Vector(Box::new(MoveTypeLayout::U8))
    ]));
    
    let ctx = ValueSerDeContext::new(None);
    let value = ctx.deserialize(&corrupted_bytes, &layout).unwrap();
    
    // Now call native string functions on this invalid String
    // This triggers undefined behavior via from_utf8_unchecked
    // Result: potential memory corruption, crashes, or consensus divergence
}
```

Without a demonstrated method to inject invalid UTF-8 through an unprivileged attack path, this vulnerability cannot be fully exploited in practice.

---

**Notes:**

This finding represents a **defense-in-depth weakness** rather than a directly exploitable vulnerability. While the impact is severe (Critical severity per bug bounty criteria), the likelihood depends on discovering a separate vulnerability that allows storage corruption. The codebase should implement validation-on-load to prevent catastrophic failures if such a vulnerability exists or if storage corruption occurs.

### Citations

**File:** aptos-move/framework/move-stdlib/sources/string.move (L17-20)
```text
    public fun utf8(bytes: vector<u8>): String {
        assert!(internal_check_utf8(&bytes), EINVALID_UTF8);
        String{bytes}
    }
```

**File:** third_party/move/move-vm/runtime/src/data_cache.rs (L299-314)
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
```

**File:** third_party/move/move-vm/types/src/values/values_impl.rs (L5132-5138)
```rust
            L::Struct(struct_layout) => {
                let seed = DeserializationSeed {
                    ctx: self.ctx,
                    layout: struct_layout,
                };
                Ok(Value::struct_(seed.deserialize(deserializer)?))
            },
```

**File:** third_party/move/move-vm/types/src/values/values_impl.rs (L5141-5143)
```rust
            L::Vector(layout) => Ok(match layout.as_ref() {
                L::U8 => Value::vector_u8(Vec::deserialize(deserializer)?),
                L::U16 => Value::vector_u16(Vec::deserialize(deserializer)?),
```

**File:** aptos-move/framework/move-stdlib/src/natives/string.rs (L75-78)
```rust
    let ok = unsafe {
        // This is safe because we guarantee the bytes to be utf8.
        std::str::from_utf8_unchecked(s_ref.as_slice()).is_char_boundary(i as usize)
    };
```

**File:** aptos-move/framework/move-stdlib/src/natives/string.rs (L110-114)
```rust
    let s_str = unsafe {
        // This is safe because we guarantee the bytes to be utf8.
        std::str::from_utf8_unchecked(s_ref.as_slice())
    };
    let v = Value::vector_u8(s_str[i..j].as_bytes().iter().cloned());
```

**File:** aptos-move/framework/move-stdlib/src/natives/string.rs (L136-143)
```rust
    let r_str = unsafe { std::str::from_utf8_unchecked(r_ref.as_slice()) };

    context.charge(STRING_INDEX_OF_PER_BYTE_PATTERN * NumBytes::new(r_str.len() as u64))?;

    let s_arg = safely_pop_arg!(args, VectorRef);
    let s_ref = s_arg.as_bytes_ref();
    let s_str = unsafe { std::str::from_utf8_unchecked(s_ref.as_slice()) };
    let pos = match s_str.find(r_str) {
```

**File:** aptos-move/framework/aptos-stdlib/sources/from_bcs.move (L55-60)
```text
    public fun to_string(v: vector<u8>): String {
        // To make this safe, we need to evaluate the utf8 invariant.
        let s = from_bytes<String>(v);
        assert!(string::internal_check_utf8(s.bytes()), EINVALID_UTF8);
        s
    }
```
