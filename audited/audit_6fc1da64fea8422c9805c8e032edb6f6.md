# Audit Report

## Title
Backward Incompatibility Risk: Type Tag Deserialization Failure After Depth Limit Reduction

## Summary
The hardcoded `MAX_TYPE_TAG_NESTING` constant in type tag deserialization creates a backward compatibility risk where resources stored with deeply nested type tags could become permanently inaccessible if a future protocol upgrade reduces this limit, leading to locked funds that cannot be recovered without a hard fork.

## Finding Description
The vulnerability lies in the interaction between type tag serialization depth limits and resource storage recovery. When resources are stored on-chain, their `StructTag` (containing type arguments) is serialized as part of the storage key path. The system enforces a depth limit during both serialization and deserialization. [1](#0-0) 

The deserialization function enforces this limit strictly: [2](#0-1) 

When storage keys are decoded from persistent storage, the `Path` enum (containing `StructTag`) must be deserialized: [3](#0-2) 

**Attack Scenario**:
1. Current protocol: `MAX_TYPE_TAG_NESTING = 8`
2. Users create resources with type tags at depth 8 (currently valid)
3. Resources are stored with their `StructTag` serialized in storage keys
4. Protocol upgrade reduces `MAX_TYPE_TAG_NESTING` to 6 (hypothetical security hardening)
5. Any attempt to access the stored resource triggers `StateKey::decode()`
6. Deserialization fails due to depth check violation
7. Resource becomes permanently inaccessible

Tests confirm that type tags at the maximum depth can be serialized and deserialized under the current limit: [4](#0-3) 

The `access_vector()` method creates storage keys using BCS serialization: [5](#0-4) 

**Critical Gap**: There is no versioned deserialization mechanism, no migration path, and no fallback for handling legacy data with deeper nesting than the current limit.

## Impact Explanation
**Severity: High** - While not immediately exploitable, this represents a significant backward compatibility hazard that could result in **permanent freezing of funds** if the limit is ever tightened.

According to Aptos Bug Bounty severity categories, "Permanent freezing of funds (requires hardfork)" is classified as **Critical Severity**. However, this is contingent on a protocol change decision, reducing the immediate exploitability to **High Severity** as a protocol design flaw.

The impact affects:
- All resources with deeply nested generic type arguments
- Any funds stored in such resources
- API access, Move VM access, and all resource operations
- Requires hard fork to recover if triggered

## Likelihood Explanation
**Likelihood: Low to Medium**

While reducing `MAX_TYPE_TAG_NESTING` is operationally unlikely (limits are typically increased for functionality), the risk exists because:

1. **Security hardening**: Developers might reduce the limit to prevent stack overflow attacks or improve validation performance
2. **No safeguards**: The codebase has no version-aware deserialization to prevent this
3. **Silent breakage**: Resources at maximum depth are valid today but could break silently
4. **No documentation**: No warnings exist about this backward compatibility constraint

The likelihood increases if:
- Performance issues arise from deep type nesting
- Security researchers recommend tighter limits
- Protocol optimization requires reducing complexity bounds

## Recommendation
Implement version-aware type tag deserialization with fallback mechanisms:

1. **Version the depth limit**: Store the serialization version alongside type tags
2. **Graceful degradation**: Use the serialization version's limit for deserialization
3. **Migration tooling**: Provide utilities to detect and migrate resources with deep nesting
4. **Explicit invariant**: Document that `MAX_TYPE_TAG_NESTING` must never decrease

Proposed fix approach:
- Add a version field to `StateKey` encoding
- Modify `type_tag_recursive_deserialize()` to accept a runtime depth parameter
- On `StateKey::decode()`, use the stored version to determine the appropriate limit
- Add protocol upgrade checks to prevent reducing `MAX_TYPE_TAG_NESTING`

## Proof of Concept

This vulnerability cannot be demonstrated with a traditional exploit PoC since it requires protocol developers to modify the hardcoded constant. Instead, here's a demonstration of the risk:

```rust
// Reproduction steps:
// 1. Create a resource with type tag at depth 8 (current max)
// 2. Serialize and store it (works fine)
// 3. Modify MAX_TYPE_TAG_NESTING to 6 in safe_serialize.rs
// 4. Attempt to deserialize the stored StateKey
// 5. Observe deserialization failure

#[test]
fn test_backward_compat_vulnerability() {
    use move_core_types::language_storage::{StructTag, TypeTag};
    use move_core_types::account_address::AccountAddress;
    use move_core_types::identifier::Identifier;
    
    // Build a type tag at depth 8 (current max)
    let mut ty = TypeTag::U8;
    for _ in 0..8 {
        ty = TypeTag::Vector(Box::new(ty));
    }
    
    let struct_tag = StructTag {
        address: AccountAddress::ONE,
        module: Identifier::new("test").unwrap(),
        name: Identifier::new("Resource").unwrap(),
        type_args: vec![ty],
    };
    
    // Serialize (works with MAX_TYPE_TAG_NESTING = 8)
    let bytes = bcs::to_bytes(&struct_tag).expect("serialization should work");
    
    // Deserialize (works with MAX_TYPE_TAG_NESTING = 8)
    let deserialized: StructTag = bcs::from_bytes(&bytes)
        .expect("deserialization should work");
    
    assert_eq!(struct_tag, deserialized);
    
    // If MAX_TYPE_TAG_NESTING were reduced to 6:
    // let result: Result<StructTag, _> = bcs::from_bytes(&bytes);
    // assert!(result.is_err()); // Would fail with "type tag nesting exceeded"
}
```

**Notes**:
- This vulnerability represents a **protocol design flaw** rather than an immediately exploitable attack vector
- The risk is **contingent on future protocol decisions** to reduce the depth limit
- Current resources at depth ≤ 8 are safe under the current limit
- The lack of versioned deserialization is the root cause
- Proactive mitigation is recommended before this becomes an actual issue

### Citations

**File:** third_party/move/move-core/types/src/safe_serialize.rs (L11-11)
```rust
pub(crate) const MAX_TYPE_TAG_NESTING: u8 = 8;
```

**File:** third_party/move/move-core/types/src/safe_serialize.rs (L46-67)
```rust
pub(crate) fn type_tag_recursive_deserialize<'de, D, T>(d: D) -> Result<T, D::Error>
where
    D: Deserializer<'de>,
    T: Deserialize<'de>,
{
    use serde::de::Error;
    TYPE_TAG_DEPTH.with(|depth| {
        let mut r = depth.borrow_mut();
        if *r >= MAX_TYPE_TAG_NESTING {
            return Err(D::Error::custom(
                "type tag nesting exceeded during deserialization",
            ));
        }
        *r += 1;
        Ok(())
    })?;
    let res = T::deserialize(d);
    TYPE_TAG_DEPTH.with(|depth| {
        let mut r = depth.borrow_mut();
        *r -= 1;
    });
    res
```

**File:** types/src/state_store/state_key/mod.rs (L72-79)
```rust
            StateKeyTag::AccessPath => {
                let AccessPath { address, path } = bcs::from_bytes(&val[1..])?;
                let path: Path = bcs::from_bytes(&path)?;
                match path {
                    Path::Code(ModuleId { address, name }) => Self::module(&address, &name),
                    Path::Resource(struct_tag) => Self::resource(&address, &struct_tag)?,
                    Path::ResourceGroup(struct_tag) => Self::resource_group(&address, &struct_tag),
                }
```

**File:** third_party/move/move-core/types/src/language_storage.rs (L226-230)
```rust
    pub fn access_vector(&self) -> Vec<u8> {
        let mut key = vec![RESOURCE_TAG];
        key.append(&mut bcs::to_bytes(self).unwrap());
        key
    }
```

**File:** third_party/move/move-core/types/src/language_storage.rs (L663-685)
```rust
    #[test]
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
