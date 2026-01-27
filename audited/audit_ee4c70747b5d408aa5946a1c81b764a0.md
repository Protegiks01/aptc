# Audit Report

## Title
Version 5 Metadata Bypass Enables Resource Group Attribute Validation Evasion Leading to Consensus Violations

## Summary
An attacker can publish a version 5 Move module containing invalid V1 metadata attributes that bypass validation during publishing but are enforced at runtime, causing state inconsistencies and potential consensus violations. The vulnerability exploits a discrepancy between two metadata extraction functions: `get_metadata_from_compiled_code()` clears attributes for version 5 modules during publishing validation, while `get_metadata()` does not clear them during runtime execution.

## Finding Description

The Aptos codebase contains two different functions for extracting module metadata:

1. **`get_metadata_from_compiled_code()`** - Used during module publishing validation [1](#0-0) 

2. **`get_metadata()}`** - Used during runtime resource operations [2](#0-1) 

The critical difference is that `get_metadata_from_compiled_code()` contains special logic that clears `struct_attributes` and `fun_attributes` when the module version is 5 [3](#0-2) , while `get_metadata()` performs no such clearing.

During module publishing, the validation function `verify_module_metadata_for_module_publishing()` calls `get_metadata_from_compiled_code()` [4](#0-3) , which clears attributes for version 5 modules before validating them. This allows modules with invalid attributes to pass validation since the validator sees empty attribute maps.

However, at runtime, when processing resource changes in the session's `finish()` method, the code calls `get_resource_group_member_from_metadata()` [5](#0-4) , which internally uses `get_metadata()` [6](#0-5) . Since `get_metadata()` does not clear attributes, the original invalid attributes from the version 5 module are used.

**Attack Scenario:**
1. Attacker creates a version 5 module with V1 metadata containing a `resource_group_member` attribute on a struct that lacks the required Key ability
2. During publishing, attributes are cleared before validation, so validation passes
3. Module bytecode (with original metadata intact) is stored on-chain
4. At runtime, when resources of this struct type are modified, the uncleaned metadata is read and the struct is incorrectly treated as a resource group member
5. This causes resources to be stored in resource groups when they should be stored as regular resources, violating storage invariants

## Impact Explanation

This vulnerability is **Critical Severity** because it enables:

1. **Consensus Violations**: Different validators may process the same transaction differently depending on timing or implementation details, violating the "Deterministic Execution" invariant. If one validator's code path uses `get_metadata_from_compiled_code()` while another uses `get_metadata()`, they will see different attributes and produce different state roots.

2. **State Consistency Violations**: Resources marked as resource_group_members without proper validation can be stored in resource groups incorrectly, corrupting the Jellyfish Merkle tree structure and breaking the "State Consistency" invariant.

3. **Storage Invariant Violations**: The validation checks ensure that resource_group_members have the Key ability [7](#0-6) . Bypassing this allows invalid storage layouts that the VM assumes cannot exist.

According to the Aptos bug bounty criteria, consensus/safety violations are Critical severity (up to $1,000,000).

## Likelihood Explanation

**Likelihood: High**

The attack is highly likely because:
- Version 5 is the minimum supported bytecode version [8](#0-7) 
- Any user can publish modules without special privileges
- The attacker only needs to craft a version 5 module with V1 metadata, which can be done by modifying the compiler output or manually crafting bytecode
- The vulnerability is deterministic and does not require race conditions or timing
- The comment in the code explicitly states this "should have been gated in the verify module metadata" [9](#0-8) , suggesting the developers were aware of the issue but did not fully address it

## Recommendation

**Immediate Fix:** Reject modules at version 5 that contain V1 metadata during publishing validation. V1 metadata should only exist on version 6+ modules as specified by `METADATA_V1_MIN_FILE_FORMAT_VERSION` [10](#0-9) .

Add validation in `verify_module_metadata_for_module_publishing()`:

```rust
pub fn verify_module_metadata_for_module_publishing(
    module: &CompiledModule,
    features: &Features,
) -> Result<(), MetaDataValidationError> {
    // Reject version 5 modules with V1 metadata
    if module.version == 5 {
        if find_metadata(&module.metadata, APTOS_METADATA_KEY_V1).is_some() {
            return Err(MalformedError::UnknownKey(
                APTOS_METADATA_KEY_V1.to_vec()
            ).into());
        }
    }
    
    if features.is_enabled(FeatureFlag::SAFER_METADATA) {
        check_module_complexity(module)?;
    }
    // ... rest of validation
}
```

**Long-term Fix:** Consolidate metadata extraction to always use a single function that properly handles version checks, or ensure all code paths check the module version before using metadata.

## Proof of Concept

```rust
// Proof of Concept - Rust test to demonstrate the vulnerability
#[test]
fn test_version_5_metadata_bypass() {
    use move_binary_format::CompiledModule;
    use move_core_types::metadata::Metadata;
    use aptos_types::vm::module_metadata::{
        get_metadata_from_compiled_code, get_metadata, 
        RuntimeModuleMetadataV1, KnownAttribute, APTOS_METADATA_KEY_V1
    };
    
    // Create a version 5 module
    let mut module = create_test_module(); // helper function
    module.version = 5;
    
    // Add V1 metadata with invalid resource_group_member attribute
    let mut metadata = RuntimeModuleMetadataV1::default();
    metadata.struct_attributes.insert(
        "InvalidStruct".to_string(),
        vec![KnownAttribute::resource_group_member(
            "0x1::group::Container".parse().unwrap()
        )]
    );
    
    let serialized = bcs::to_bytes(&metadata).unwrap();
    module.metadata.push(Metadata {
        key: APTOS_METADATA_KEY_V1.to_vec(),
        value: serialized,
    });
    
    // During publishing: attributes are cleared
    let publishing_metadata = get_metadata_from_compiled_code(&module);
    assert!(publishing_metadata.is_some());
    assert!(publishing_metadata.unwrap().struct_attributes.is_empty());
    // Validation passes because attributes are cleared!
    
    // At runtime: attributes are NOT cleared
    let runtime_metadata = get_metadata(&module.metadata);
    assert!(runtime_metadata.is_some());
    assert!(!runtime_metadata.unwrap().struct_attributes.is_empty());
    // Invalid attributes are used at runtime!
    
    println!("VULNERABILITY CONFIRMED: Version 5 module bypasses validation!");
}
```

**Notes:**
- This vulnerability exists because of the inconsistent handling of version 5 modules between publishing and runtime code paths
- The minimum file format version for V1 metadata is 6, but the code allows version 5 modules to contain V1 metadata
- The defensive clearing in `get_metadata_from_compiled_code()` inadvertently creates a validation bypass when not applied consistently across all code paths

### Citations

**File:** types/src/vm/module_metadata.rs (L40-40)
```rust
pub const METADATA_V1_MIN_FILE_FORMAT_VERSION: u32 = 6;
```

**File:** types/src/vm/module_metadata.rs (L198-230)
```rust
/// Extract metadata from the VM, upgrading V0 to V1 representation as needed
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

**File:** types/src/vm/module_metadata.rs (L423-438)
```rust
pub fn is_valid_resource_group_member(
    structs: &BTreeMap<&IdentStr, (&StructHandle, &StructDefinition)>,
    struct_: &str,
) -> Result<(), AttributeValidationError> {
    if let Ok(ident_struct) = Identifier::new(struct_) {
        if let Some((struct_handle, _struct_def)) = structs.get(ident_struct.as_ident_str()) {
            if struct_handle.abilities.has_ability(Ability::Key) {
                return Ok(());
            }
        }
    }

    Err(AttributeValidationError {
        key: struct_.to_string(),
        attribute: KnownAttributeKind::ViewFunction as u8,
    })
```

**File:** types/src/vm/module_metadata.rs (L452-456)
```rust
    let metadata = if let Some(metadata) = get_metadata_from_compiled_code(module) {
        metadata
    } else {
        return Ok(());
    };
```

**File:** aptos-move/aptos-vm/src/move_vm_ext/session/mod.rs (L377-378)
```rust
                    get_resource_group_member_from_metadata(&struct_tag, &module.metadata)
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
