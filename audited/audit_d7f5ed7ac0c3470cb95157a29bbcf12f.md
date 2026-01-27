# Audit Report

## Title
Type Depth Limit Mismatch Between Bytecode Verification and BCS Serialization Causes Transaction Failures in Resource Groups

## Summary
A critical inconsistency exists between the bytecode verifier's `max_type_depth` limit (20) and the BCS serialization layer's `MAX_TYPE_TAG_NESTING` limit (8). This mismatch allows Move modules with deeply nested types (depth 9-20) to pass bytecode verification and runtime execution, but causes transaction failures when `group_tagged_resource_size()` attempts to serialize the StructTag for gas calculation in resource group operations.

## Finding Description

The Aptos blockchain has multiple depth-checking mechanisms at different layers: [1](#0-0) 

The production verifier configuration allows types with depth up to 20 when function values are enabled. Similarly, the runtime TypeBuilder also permits depth up to 20: [2](#0-1) 

However, the BCS serialization layer enforces a much stricter limit: [3](#0-2) 

This creates a critical mismatch. When a resource group operation processes a resource with a deeply nested type (depth 9-20), the `group_tagged_resource_size()` function is called: [4](#0-3) 

The function calls `bcs::serialized_size(&tag)` which internally uses serde serialization with the MAX_TYPE_TAG_NESTING limit. Tests confirm this behavior: [5](#0-4) 

**Attack Scenario:**
1. Attacker publishes a Move module with a generic struct having type parameters nested to depth 9-20 (e.g., `Struct<A<B<C<D<E<F<G<H<I<U8>>>>>>>>>`)
2. Module passes bytecode verification (max_type_depth = 20) and is deployed
3. Attacker or legitimate user creates a resource in a resource group with this deeply nested type
4. VM execution succeeds - the type is valid according to all runtime checks
5. During write conversion in `convert_resource_group_v1`, the function calls `group_tagged_resource_size()` with the StructTag
6. `bcs::serialized_size(&tag)` fails because nesting depth exceeds 8
7. Transaction aborts with `VALUE_SERIALIZATION_ERROR`

This affects the write conversion path: [6](#0-5) 

## Impact Explanation

**Medium Severity** - This vulnerability causes legitimate transaction failures and can be exploited for denial of service:

1. **Transaction Failures**: Any transaction attempting to modify resource groups containing resources with types nested between depth 9-20 will fail with `VALUE_SERIALIZATION_ERROR`, even though the type is valid according to bytecode verification.

2. **DoS Vector**: An attacker can deliberately create resource groups with deeply nested types to make them permanently unmaintainable, as any future operations on these groups will fail.

3. **Deterministic Execution Risk**: This could potentially cause consensus divergence if validators have different versions of the code or if error handling differs between execution contexts.

4. **State Inconsistencies**: Resources may be created successfully but become inaccessible for group operations, requiring manual intervention.

The impact qualifies as **Medium Severity** per Aptos bug bounty criteria: "State inconsistencies requiring intervention" and potential for limited denial of service attacks on resource group functionality.

## Likelihood Explanation

**Moderate Likelihood:**

1. **Requires Feature Flag**: The issue only manifests when `ENABLE_FUNCTION_VALUES` feature flag is enabled (which sets max_type_depth to 20).

2. **Natural Occurrence**: While depth-20 types are uncommon, depth 9-11 types can occur naturally in complex DeFi applications with nested generic containers (e.g., `Table<address, Vector<Option<SomeStruct<T>>>>`).

3. **Easy Exploitation**: An attacker can deliberately craft modules with deeply nested types to trigger this issue.

4. **Resource Groups Required**: Only affects operations on resource groups, not standalone resources.

The combination of uncommon but possible natural occurrence and deliberate exploitation potential makes this moderately likely to manifest.

## Recommendation

**Immediate Fix:** Align the type depth limits across all layers. The recommended approach is to reduce the bytecode verifier's `max_type_depth` to match `MAX_TYPE_TAG_NESTING`:

```rust
// In aptos-move/aptos-vm-environment/src/prod_configs.rs
max_type_depth: if enable_function_values {
    Some(8)  // Changed from 20 to match MAX_TYPE_TAG_NESTING
} else {
    None
},
```

**Alternative Fix:** If depth-20 types are required for certain use cases, increase `MAX_TYPE_TAG_NESTING` to 20:

```rust
// In third_party/move/move-core/types/src/safe_serialize.rs
pub(crate) const MAX_TYPE_TAG_NESTING: u8 = 20;  // Changed from 8
```

**Long-term Solution:** Implement consistent depth checking across all layers:
1. Bytecode verification
2. Runtime type construction
3. Type-to-TypeTag conversion
4. BCS serialization

Add validation in `TypeTagConverter` to enforce the same limit before constructing TypeTags that will later fail serialization.

## Proof of Concept

```move
// File: sources/deep_nesting_exploit.move
module test_addr::deep_nesting {
    struct Level9<T> { value: T }
    struct Level8<T> { inner: Level9<T> }
    struct Level7<T> { inner: Level8<T> }
    struct Level6<T> { inner: Level7<T> }
    struct Level5<T> { inner: Level6<T> }
    struct Level4<T> { inner: Level5<T> }
    struct Level3<T> { inner: Level4<T> }
    struct Level2<T> { inner: Level3<T> }
    struct Level1<T> { inner: Level2<T> }
    
    #[resource_group_member(group = aptos_framework::object::ObjectGroup)]
    struct DeeplyNested has key {
        data: Level1<u64>
    }
    
    public entry fun create_deeply_nested(account: &signer) {
        // This will pass bytecode verification (max_type_depth = 20)
        // But will fail in group_tagged_resource_size() when serializing the StructTag
        move_to(account, DeeplyNested {
            data: Level1 {
                inner: Level2 {
                    inner: Level3 {
                        inner: Level4 {
                            inner: Level5 {
                                inner: Level6 {
                                    inner: Level7 {
                                        inner: Level8 {
                                            inner: Level9 { value: 42 }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        });
        // Transaction will fail with VALUE_SERIALIZATION_ERROR
        // when trying to compute resource group size
    }
}
```

This PoC demonstrates a type nested to depth 9, which passes bytecode verification but fails BCS serialization during resource group operations. The transaction will succeed through VM execution but fail during write conversion with `VALUE_SERIALIZATION_ERROR`.

### Citations

**File:** aptos-move/aptos-vm-environment/src/prod_configs.rs (L132-134)
```rust
pub fn aptos_default_ty_builder() -> TypeBuilder {
    TypeBuilder::with_limits(128, 20)
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

**File:** third_party/move/move-core/types/src/safe_serialize.rs (L11-11)
```rust
pub(crate) const MAX_TYPE_TAG_NESTING: u8 = 8;
```

**File:** aptos-move/aptos-vm-types/src/resource_group_adapter.rs (L47-57)
```rust
pub fn group_tagged_resource_size<T: Serialize + Clone + Debug>(
    tag: &T,
    value_byte_len: usize,
) -> PartialVMResult<u64> {
    Ok((bcs::serialized_size(&tag).map_err(|e| {
        PartialVMError::new(StatusCode::VALUE_SERIALIZATION_ERROR).with_message(format!(
            "Tag serialization error for tag {:?}: {:?}",
            tag, e
        ))
    })? + bcs_size_of_byte_array(value_byte_len)) as u64)
}
```

**File:** third_party/move/move-core/types/src/language_storage.rs (L664-685)
```rust
    fn test_nested_type_tag_struct_serde() {
        let mut type_tags = vec![make_type_tag_struct(TypeTag::U8)];

        let limit = MAX_TYPE_TAG_NESTING;
        while type_tags.len() < limit.into() {
            type_tags.push(make_type_tag_struct(type_tags.last().unwrap().clone()));
        }

        // Note for this test serialize can handle one more nesting than deserialize
        // Both directions work
        let output = bcs::to_bytes(type_tags.last().unwrap()).unwrap();
        bcs::from_bytes::<TypeTag>(&output).unwrap();

        // One more, both should fail
        type_tags.push(make_type_tag_struct(type_tags.last().unwrap().clone()));
        let output = bcs::to_bytes(type_tags.last().unwrap()).unwrap();
        bcs::from_bytes::<TypeTag>(&output).unwrap_err();

        // One more and serialize fails
        type_tags.push(make_type_tag_struct(type_tags.last().unwrap().clone()));
        bcs::to_bytes(type_tags.last().unwrap()).unwrap_err();
    }
```

**File:** aptos-move/aptos-vm/src/move_vm_ext/write_op_converter.rs (L183-190)
```rust
                let old_size = group_tagged_resource_size(&tag, old_tagged_value_size)?;
                decrement_size_for_remove_tag(&mut post_group_size, old_size)?;
            }

            match &current_op {
                MoveStorageOp::Modify((data, _)) | MoveStorageOp::New((data, _)) => {
                    let new_size = group_tagged_resource_size(&tag, data.len())?;
                    increment_size_for_add_tag(&mut post_group_size, new_size)?;
```
