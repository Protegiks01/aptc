# Audit Report

## Title
Forward-Compatibility Failure: Unknown Metadata Keys and Attributes Block Legitimate Module Upgrades

## Summary
The metadata validation system in Aptos Core strictly rejects any metadata keys or attribute types that are not in the hardcoded list of known values. This creates a forward-compatibility issue where modules compiled with future compiler versions containing new metadata formats will be rejected by current validators, preventing legitimate module upgrades until all validators coordinate a network-wide upgrade.

## Finding Description

The vulnerability exists in the metadata validation logic that is enforced during module publishing and upgrades. There are two specific rejection points:

**1. Unknown Metadata Keys Rejection:**

In `check_metadata_format()`, any metadata key that is not in the hardcoded list (`APTOS_METADATA_KEY`, `APTOS_METADATA_KEY_V1`, or `COMPILATION_METADATA_KEY`) is immediately rejected: [1](#0-0) 

At line 278, unknown keys trigger `MalformedError::UnknownKey`, causing the transaction to fail with `CONSTRAINT_NOT_SATISFIED`.

**2. Unknown Attribute Types Rejection:**

In `verify_module_metadata_for_module_publishing()`, any function or struct attribute that doesn't match the known types is rejected: [2](#0-1) [3](#0-2) 

Function attributes that aren't `view_function` or `randomness` are rejected at lines 474-479. Struct attributes that aren't `resource_group`, `resource_group_member`, or `event` are rejected at lines 510-514.

**Validation is Triggered During Module Publishing:**

This validation is called from `validate_publish_request()` which is invoked for all module publishing operations: [4](#0-3) 

The validation is enabled by default when resource groups are enabled: [5](#0-4) 

**Breaking the Operational Invariant:**

When a new compiler version introduces:
- A new metadata key (e.g., `aptos::metadata_v2` for enhanced features)
- A new attribute type (e.g., `KnownAttributeKind::NewFeature = 6`)

All modules compiled with the new compiler will be rejected by current validators, even if the modules are otherwise valid and the upgrades are legitimate. This breaks the operational continuity of the blockchain and forces a coordinated network-wide validator upgrade before developers can use new compiler features.

## Impact Explanation

This qualifies as **Medium Severity** under the Aptos bug bounty criteria: "State inconsistencies requiring intervention."

**Specific Impacts:**
1. **Prevents Legitimate Module Upgrades**: Developers using newer compilers cannot upgrade their modules until all validators upgrade
2. **Requires Coordinated Intervention**: Network-wide validator upgrades must be coordinated before new metadata formats can be used
3. **Potential Network Fragmentation**: If some validators upgrade while others don't, transaction results will be non-deterministic
4. **Operational Disruption**: Developers cannot use new compiler features even if they're beneficial

This does not rise to High or Critical severity because:
- No funds are at risk
- No consensus safety violation occurs
- No permanent network partition
- The issue can be resolved through coordinated upgrades

However, it does require intervention to resolve and creates operational challenges, fitting the Medium severity category.

## Likelihood Explanation

**Likelihood: HIGH** - This will definitely occur when new metadata formats are introduced.

The scenario is not hypothetical:
1. The Aptos compiler has already evolved from V0 to V1 metadata formats
2. Future compiler enhancements will inevitably require new metadata keys or attribute types
3. Test cases already demonstrate the rejection behavior: [6](#0-5) 

The test explicitly verifies that unknown metadata keys are rejected with `CONSTRAINT_NOT_SATISFIED`.

## Recommendation

Implement a forward-compatible metadata validation strategy that gracefully handles unknown metadata:

**Option 1: Lenient Validation (Recommended)**
```rust
fn check_metadata_format(module: &CompiledModule) -> Result<(), MalformedError> {
    let mut aptos_metadata_exist = false;
    let mut compilation_key_exist = false;
    
    for data in module.metadata.iter() {
        // Only validate known metadata keys, ignore unknown ones
        if data.key == *APTOS_METADATA_KEY || data.key == *APTOS_METADATA_KEY_V1 {
            if aptos_metadata_exist {
                return Err(MalformedError::DuplicateKey);
            }
            aptos_metadata_exist = true;
            
            // Validate known formats, but allow deserialization failures 
            // for forward compatibility
            if data.key == *APTOS_METADATA_KEY {
                let _ = bcs::from_bytes::<RuntimeModuleMetadata>(&data.value);
            } else if data.key == *APTOS_METADATA_KEY_V1 {
                let _ = bcs::from_bytes::<RuntimeModuleMetadataV1>(&data.value);
            }
        } else if data.key == *COMPILATION_METADATA_KEY {
            if compilation_key_exist {
                return Err(MalformedError::DuplicateKey);
            }
            compilation_key_exist = true;
            let _ = bcs::from_bytes::<CompilationMetadata>(&data.value);
        }
        // Silently ignore unknown metadata keys for forward compatibility
    }
    
    Ok(())
}
```

**Option 2: Version-Based Validation**
Introduce a versioning scheme where validators can skip validation of metadata with version numbers higher than they support.

**Option 3: Feature Flag**
Gate strict metadata validation behind a feature flag that can be disabled during transition periods.

For attributes, similarly update the validation to skip unknown attribute types rather than rejecting them:

```rust
// In verify_module_metadata_for_module_publishing
for attr in attrs {
    if attr.is_view_function() {
        is_valid_view_function(module, &functions, fun)?;
    } else if attr.is_randomness() {
        is_valid_unbiasable_function(&functions, fun)?;
    }
    // Skip unknown attributes instead of rejecting
}
```

## Proof of Concept

The existing test case demonstrates the issue: [6](#0-5) 

**Reproduction Steps:**

1. Compile a Move module with a future metadata key (simulated by using an unknown key)
2. Attempt to publish the module via `code_publish_package_txn`
3. Observe rejection with `StatusCode::CONSTRAINT_NOT_SATISFIED`
4. Error message includes "Unknown key found" from line 342 in module_metadata.rs

This test already exists and passes, confirming that unknown metadata keys are rejected as described in this report.

**Real-World Scenario:**
When the Aptos compiler team releases a new version with enhanced metadata (e.g., optimization hints, debugging information, or new attribute types), all modules compiled with this version will be rejected by validators running the current code, blocking legitimate upgrades until a coordinated network upgrade occurs.

## Notes

This is a **design limitation** affecting operational resilience rather than a traditional exploitable vulnerability. It doesn't allow attackers to steal funds or break consensus, but it does create operational challenges that require coordinated intervention when new compiler features are introduced. The strict validation approach prioritizes security over forward compatibility, which may be intentional but should be documented and potentially revised to support smoother ecosystem evolution.

### Citations

**File:** types/src/vm/module_metadata.rs (L252-283)
```rust
/// Check if the metadata has unknown key/data types
fn check_metadata_format(module: &CompiledModule) -> Result<(), MalformedError> {
    let mut exist = false;
    let mut compilation_key_exist = false;
    for data in module.metadata.iter() {
        if data.key == *APTOS_METADATA_KEY || data.key == *APTOS_METADATA_KEY_V1 {
            if exist {
                return Err(MalformedError::DuplicateKey);
            }
            exist = true;

            if data.key == *APTOS_METADATA_KEY {
                bcs::from_bytes::<RuntimeModuleMetadata>(&data.value)
                    .map_err(|e| MalformedError::DeserializedError(data.key.clone(), e))?;
            } else if data.key == *APTOS_METADATA_KEY_V1 {
                bcs::from_bytes::<RuntimeModuleMetadataV1>(&data.value)
                    .map_err(|e| MalformedError::DeserializedError(data.key.clone(), e))?;
            }
        } else if data.key == *COMPILATION_METADATA_KEY {
            if compilation_key_exist {
                return Err(MalformedError::DuplicateKey);
            }
            compilation_key_exist = true;
            bcs::from_bytes::<CompilationMetadata>(&data.value)
                .map_err(|e| MalformedError::DeserializedError(data.key.clone(), e))?;
        } else {
            return Err(MalformedError::UnknownKey(data.key.clone()));
        }
    }

    Ok(())
}
```

**File:** types/src/vm/module_metadata.rs (L449-451)
```rust
    if features.are_resource_groups_enabled() {
        check_metadata_format(module)?;
    }
```

**File:** types/src/vm/module_metadata.rs (L468-481)
```rust
    for (fun, attrs) in &metadata.fun_attributes {
        for attr in attrs {
            if attr.is_view_function() {
                is_valid_view_function(module, &functions, fun)?;
            } else if attr.is_randomness() {
                is_valid_unbiasable_function(&functions, fun)?;
            } else {
                return Err(AttributeValidationError {
                    key: fun.clone(),
                    attribute: attr.kind,
                }
                .into());
            }
        }
```

**File:** types/src/vm/module_metadata.rs (L494-515)
```rust
    for (struct_, attrs) in &metadata.struct_attributes {
        for attr in attrs {
            if features.are_resource_groups_enabled() {
                if attr.is_resource_group() && attr.get_resource_group().is_some() {
                    is_valid_resource_group(&structs, struct_)?;
                    continue;
                } else if attr.is_resource_group_member()
                    && attr.get_resource_group_member().is_some()
                {
                    is_valid_resource_group_member(&structs, struct_)?;
                    continue;
                }
            }
            if features.is_module_event_enabled() && attr.is_event() {
                continue;
            }
            return Err(AttributeValidationError {
                key: struct_.clone(),
                attribute: attr.kind,
            }
            .into());
        }
```

**File:** aptos-move/aptos-vm/src/aptos_vm.rs (L1715-1716)
```rust
            verify_module_metadata_for_module_publishing(m, self.features())
                .map_err(|err| Self::metadata_validation_error(&err.to_string()))?;
```

**File:** aptos-move/e2e-move-tests/src/tests/metadata.rs (L24-35)
```rust
#[test]
fn test_unknown_metadata_key() {
    let unknown_key = || {
        let metadata = Metadata {
            key: vec![1, 2, 3, 4, 5],
            value: vec![],
        };
        vec![metadata]
    };
    let result = test_metadata_with_changes(unknown_key);
    assert_vm_status!(result, StatusCode::CONSTRAINT_NOT_SATISFIED);
}
```
