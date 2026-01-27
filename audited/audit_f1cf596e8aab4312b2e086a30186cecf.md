# Audit Report

## Title
Version 5 Module Metadata Validation Bypass Allows Invalid Attributes to Affect Runtime Behavior

## Summary
The metadata validation mechanism for Move module publishing contains a critical inconsistency between validation-time and runtime metadata extraction for version 5 modules. During publishing validation, `get_metadata_from_compiled_code()` clears struct and function attributes for v5 modules, but at runtime, `get_metadata()` does not perform this clearing, allowing invalid attributes to bypass validation and affect execution behavior. [1](#0-0) 

## Finding Description

The vulnerability stems from two different metadata extraction functions that handle version 5 modules inconsistently:

**During Publishing Validation:**
When `verify_module_metadata_for_module_publishing()` is called during module publishing, it uses `get_metadata_from_compiled_code()` which explicitly clears `struct_attributes` and `fun_attributes` for version 5 modules: [2](#0-1) 

This cleared metadata is then validated, ensuring it passes all constraints. The same clearing occurs in resource group validation: [3](#0-2) 

**At Runtime:**
However, when metadata is accessed during transaction execution, the system uses `get_metadata()` which does NOT clear v5 attributes: [4](#0-3) 

This function directly deserializes and caches metadata without version-specific clearing.

**Exploitation Path:**
1. Attacker creates a version 5 `CompiledModule` with V1 metadata containing invalid attributes (e.g., incorrect `resource_group_member` annotations, fake `view_function` attributes, or malicious `randomness` annotations)
2. Submit module for publishing via transaction
3. During `verify_module_metadata_for_module_publishing()`, attributes are cleared before validation
4. During `validate_resource_groups()`, attributes are cleared again before resource group validation
5. All validations pass because they check cleared metadata
6. Module is published to blockchain with original, uncleared metadata in the metadata section
7. At runtime, when functions like `get_resource_group_member_from_metadata()` access metadata: [5](#0-4) 

Or when `get_randomness_annotation_for_entry_function()` checks for randomness attributes: [6](#0-5) 

The uncleared, invalid attributes become active and affect execution behavior.

**Version 5 Viability:**
Version 5 modules can still be published as VERSION_MIN is set to VERSION_5: [7](#0-6) 

And networks without specific feature flags enabled will accept version 5 modules: [8](#0-7) 

## Impact Explanation

This vulnerability has **Medium severity** with potential for state inconsistency:

1. **Resource Group Storage Corruption**: An attacker can mark structs with invalid `resource_group_member` attributes. At runtime, resources would be accessed via incorrect storage keys, leading to:
   - Resources stored/retrieved from wrong locations
   - State inconsistency between storage layout expectations
   - Potential consensus divergence if different validators process transactions differently

2. **Randomness Annotation Abuse**: Invalid `randomness` annotations can be attached to functions that shouldn't have them, affecting when sessions are marked as unbiasable: [9](#0-8) 

3. **Deterministic Execution Violation**: Different validators may interpret the same transaction differently if metadata affects execution paths, violating the critical invariant that all validators must produce identical state roots.

This meets the **Medium Severity** criteria: "State inconsistencies requiring intervention" and could escalate to consensus issues.

## Likelihood Explanation

**Likelihood: Medium**

The attack is feasible because:
- An attacker only needs the ability to publish Move modules (no special privileges required)
- Version 5 modules are explicitly supported (VERSION_MIN = 5)
- The exploit requires minimal technical sophistication - simply compile a v5 module with custom metadata
- The inconsistency is structural and guaranteed to work if v5 modules are accepted

However, likelihood is reduced by:
- Most modern networks likely have VERSION_6+ feature flags enabled
- Version 5 is an older format, though still officially supported
- The impact requires specific runtime code paths to access the invalid metadata

## Recommendation

**Immediate Fix:**
The `get_metadata()` function should also clear v5 attributes to maintain consistency with validation-time behavior:

```rust
pub fn get_metadata(md: &[Metadata]) -> Option<Arc<RuntimeModuleMetadataV1>> {
    if let Some(data) = find_metadata(md, APTOS_METADATA_KEY_V1) {
        V1_METADATA_CACHE.with(|ref_cell| {
            let mut cache = ref_cell.borrow_mut();
            if let Some(meta) = cache.get(&data.value) {
                meta.clone()
            } else {
                let mut meta = bcs::from_bytes::<RuntimeModuleMetadataV1>(&data.value)
                    .ok()
                    .map(Arc::new);
                // Clear v5 attributes for consistency
                // Note: Need access to version, may require API change
                meta
            }
        })
    } // ... rest of function
}
```

**Better Long-term Fix:**
Reject version 5 modules with V1 metadata during publishing validation, as indicated by the comment in the code. Add explicit validation:

```rust
pub fn verify_module_metadata_for_module_publishing(
    module: &CompiledModule,
    features: &Features,
) -> Result<(), MetaDataValidationError> {
    // Reject v5 modules with V1 metadata
    if module.version() == 5 {
        if find_metadata(module.metadata(), APTOS_METADATA_KEY_V1).is_some() {
            return Err(MetaDataValidationError::Malformed(
                MalformedError::UnknownKey(APTOS_METADATA_KEY_V1.to_vec())
            ));
        }
    }
    // ... rest of validation
}
```

## Proof of Concept

```move
// This Move module would be compiled to version 5 bytecode
// with manually injected V1 metadata containing invalid resource_group_member attribute

module 0x1::exploit {
    struct MyResource has key {
        value: u64
    }
    
    // At publishing time, the resource_group_member attribute in metadata
    // pointing to a non-existent resource group would be cleared during validation
    // But at runtime, get_metadata() would retrieve the uncleared attribute
    // causing the resource to be accessed via wrong storage key
}
```

**Rust reproduction steps:**
1. Create a CompiledModule with version set to 5
2. Manually inject V1 metadata with `struct_attributes` containing invalid `resource_group_member` annotation
3. Serialize and submit for publishing
4. Observe validation passes (attributes cleared)
5. After publishing, call `get_resource_group_member_from_metadata()` on the stored module
6. Observe invalid attribute is returned, not cleared

## Notes

The comment at line 293 of `module_metadata.rs` acknowledges this issue: "Note, this should have been gated in the verify module metadata" - indicating the developers were aware that clearing attributes post-deserialization is a workaround rather than proper validation. The proper fix should reject v5 modules with V1 metadata entirely during publishing, as v5 predates the METADATA_V1_MIN_FILE_FORMAT_VERSION of 6. [10](#0-9)

### Citations

**File:** types/src/vm/module_metadata.rs (L199-230)
```rust
pub fn get_metadata(md: &[Metadata]) -> Option<Arc<RuntimeModuleMetadataV1>> {
    if let Some(data) = find_metadata(md, APTOS_METADATA_KEY_V1) {
        V1_METADATA_CACHE.with(|ref_cell| {
            let mut cache = ref_cell.borrow_mut();
            if let Some(meta) = cache.get(&data.value) {
                meta.clone()
            } else {
                let meta = bcs::from_bytes::<RuntimeModuleMetadataV1>(&data.value)
                    .ok()
                    .map(Arc::new);
                cache.put(data.value.clone(), meta.clone());
                meta
            }
        })
    } else if let Some(data) = find_metadata(md, APTOS_METADATA_KEY) {
        V0_METADATA_CACHE.with(|ref_cell| {
            let mut cache = ref_cell.borrow_mut();
            if let Some(meta) = cache.get(&data.value) {
                meta.clone()
            } else {
                let meta = bcs::from_bytes::<RuntimeModuleMetadata>(&data.value)
                    .ok()
                    .map(RuntimeModuleMetadata::upgrade)
                    .map(Arc::new);
                cache.put(data.value.clone(), meta.clone());
                meta
            }
        })
    } else {
        None
    }
}
```

**File:** types/src/vm/module_metadata.rs (L234-250)
```rust
pub fn get_randomness_annotation_for_entry_function(
    entry_func: &EntryFunction,
    metadata: &[Metadata],
) -> Option<RandomnessAnnotation> {
    get_metadata(metadata).and_then(|metadata| {
        metadata
            .fun_attributes
            .get(entry_func.function().as_str())
            .map(|attrs| {
                attrs
                    .iter()
                    .filter_map(KnownAttribute::try_as_randomness_annotation)
                    .next()
            })
            .unwrap_or(None)
    })
}
```

**File:** types/src/vm/module_metadata.rs (L287-308)
```rust
pub fn get_metadata_from_compiled_code(
    code: &impl CompiledCodeMetadata,
) -> Option<RuntimeModuleMetadataV1> {
    if let Some(data) = find_metadata(code.metadata(), APTOS_METADATA_KEY_V1) {
        let mut metadata = bcs::from_bytes::<RuntimeModuleMetadataV1>(&data.value).ok();
        // Clear out metadata for v5, since it shouldn't have existed in the first place and isn't
        // being used. Note, this should have been gated in the verify module metadata.
        if code.version() == 5 {
            if let Some(metadata) = metadata.as_mut() {
                metadata.struct_attributes.clear();
                metadata.fun_attributes.clear();
            }
        }
        metadata
    } else if let Some(data) = find_metadata(code.metadata(), APTOS_METADATA_KEY) {
        // Old format available, upgrade to new one on the fly
        let data_v0 = bcs::from_bytes::<RuntimeModuleMetadata>(&data.value).ok()?;
        Some(data_v0.upgrade())
    } else {
        None
    }
}
```

**File:** aptos-move/aptos-vm/src/verifier/resource_groups.rs (L119-124)
```rust
    let (new_groups, mut new_members) =
        if let Some(metadata) = get_metadata_from_compiled_code(new_module) {
            extract_resource_group_metadata(&metadata)?
        } else {
            (BTreeMap::new(), BTreeMap::new())
        };
```

**File:** aptos-move/aptos-vm/src/data_cache.rs (L50-60)
```rust
pub fn get_resource_group_member_from_metadata(
    struct_tag: &StructTag,
    metadata: &[Metadata],
) -> Option<StructTag> {
    let metadata = get_metadata(metadata)?;
    metadata
        .struct_attributes
        .get(struct_tag.name.as_ident_str().as_str())?
        .iter()
        .find_map(|attr| attr.get_resource_group_member())
}
```

**File:** third_party/move/move-binary-format/src/file_format_common.rs (L562-562)
```rust
pub const VERSION_MIN: u32 = VERSION_5;
```

**File:** types/src/on_chain_config/aptos_features.rs (L485-499)
```rust
    pub fn get_max_binary_format_version(&self) -> u32 {
        if self.is_enabled(FeatureFlag::VM_BINARY_FORMAT_V10) {
            file_format_common::VERSION_10
        } else if self.is_enabled(FeatureFlag::VM_BINARY_FORMAT_V9) {
            file_format_common::VERSION_9
        } else if self.is_enabled(FeatureFlag::VM_BINARY_FORMAT_V8) {
            file_format_common::VERSION_8
        } else if self.is_enabled(FeatureFlag::VM_BINARY_FORMAT_V7) {
            file_format_common::VERSION_7
        } else if self.is_enabled(FeatureFlag::VM_BINARY_FORMAT_V6) {
            file_format_common::VERSION_6
        } else {
            file_format_common::VERSION_5
        }
    }
```

**File:** aptos-move/aptos-vm/src/aptos_vm.rs (L983-991)
```rust
            if function.is_friend_or_private() {
                let maybe_randomness_annotation = get_randomness_annotation_for_entry_function(
                    entry_fn,
                    &function.owner_as_module()?.metadata,
                );
                if maybe_randomness_annotation.is_some() {
                    session.mark_unbiasable();
                }
            }
```
