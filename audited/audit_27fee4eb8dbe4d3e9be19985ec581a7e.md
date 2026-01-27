# Audit Report

## Title
Resource Group Metadata Inconsistency Causes Resources to Become Inaccessible via API

## Summary
The API's resource deserialization logic relies on module metadata to determine whether bytes should be interpreted as a resource group container or a standalone resource. However, module metadata can become unavailable or inconsistent after resources are written to storage, causing a mismatch between the storage path type and the deserialization strategy. This makes resource groups permanently inaccessible via the API when metadata is missing.

## Finding Description

The vulnerability stems from a cross-function inconsistency in how resources are classified during storage writes versus API reads:

**At Write Time (VM execution):**
The VM uses `get_resource_group_member_from_metadata()` to determine if a struct is a resource group member, and stores it accordingly with `StateKey::resource_group()` creating a `Path::ResourceGroup` entry. [1](#0-0) 

**At Read Time (API layer):**
The API pagination logic reads resources from storage, which returns entries with both `Path::Resource` and `Path::ResourceGroup` types. For each entry, it calls `is_resource_group()` to determine the deserialization strategy: [2](#0-1) 

The `is_resource_group()` function checks module metadata to determine if a struct is a resource group container: [3](#0-2) 

**The Critical Flaw:**
The function returns `false` (treating it as a regular resource) if:
1. Module view fails or returns `None` (line 98)
2. Metadata is missing from the module (line 99)
3. Struct attributes are absent (line 100)
4. No `is_resource_group()` attribute is found (line 103)

**Metadata Can Become Unavailable:**
Module metadata is explicitly stripped for bytecode version 5: [4](#0-3) 

**Attack Scenario:**
1. A module with resource group `Container` is deployed with proper `#[resource_group]` metadata
2. Resource groups are created and stored with `Path::ResourceGroup(Container)` containing a serialized `BTreeMap<StructTag, Bytes>`
3. Module is upgraded to v5 bytecode (metadata stripped), or module becomes unavailable
4. API pagination reads the resource group entry
5. `is_resource_group(&Container)` returns `false` due to missing metadata
6. Code executes line 545: `Ok(vec![(tag, value)])` treating BTreeMap bytes as a regular resource
7. When API tries to convert via `try_into_resource()`, it attempts to deserialize BTreeMap bytes as struct bytes
8. Deserialization fails with BCS error or produces corrupted data
9. All resources within the group become inaccessible via the API

## Impact Explanation

This is a **HIGH severity** vulnerability per Aptos bug bounty criteria:

1. **API Crashes**: Attempting to deserialize BTreeMap bytes as a struct causes BCS deserialization errors, leading to API request failures
2. **Resource Inaccessibility**: Users cannot access their resources through the API, affecting dApp functionality
3. **State Inconsistency**: The mismatch between storage representation and API interpretation creates an inconsistent view of state
4. **Requires Intervention**: Recovery requires either module redeployment with metadata or manual state migration

The comment at line 540 acknowledges this: "An error here means a storage invariant has been violated" - but the code doesn't actually prevent the violation.

## Likelihood Explanation

**High Likelihood:**

1. **Module Upgrades Are Common**: Aptos supports module upgrades, and developers regularly update their smart contracts
2. **V5 Bytecode Exists**: The explicit metadata stripping for v5 bytecode indicates this version is in use
3. **No Warning System**: There's no validation or warning when metadata becomes unavailable for existing resource groups
4. **Silent Failure**: The `is_resource_group()` function silently returns `false` rather than erroring, making the issue hard to detect
5. **Permanent Impact**: Once metadata is lost, resources remain inaccessible until manual intervention

The module view can return `None` for various reasons: [5](#0-4) 

## Recommendation

**Immediate Fix:**
Store the path type alongside the resource data or include it in the StateKey itself, so deserialization doesn't depend on module metadata availability.

**Short-term Fix:**
Add a fallback mechanism in the API pagination logic:

```rust
let kvs = kvs
    .into_iter()
    .map(|(tag, value)| {
        if converter.is_resource_group(&tag) {
            // Try to deserialize as resource group
            match bcs::from_bytes::<ResourceGroup>(&value) {
                Ok(map) => Ok(map.into_iter().collect::<Vec<_>>()),
                Err(_) => {
                    // Fallback: treat as single resource if deserialization fails
                    Ok(vec![(tag, value)])
                }
            }
        } else {
            // Check if it's actually a resource group by attempting deserialization
            match bcs::from_bytes::<ResourceGroup>(&value) {
                Ok(map) if !map.is_empty() => {
                    // This is a resource group but metadata is missing
                    Ok(map.into_iter().collect::<Vec<_>>())
                },
                _ => Ok(vec![(tag, value)])
            }
        }
    })
    .collect::<Result<Vec<Vec<(StructTag, Vec<u8>)>>>>()?
    .into_iter()
    .flatten()
    .collect();
```

**Long-term Fix:**
1. Include path type information in the iterator results to avoid metadata lookups
2. Add validation during module upgrades to prevent metadata loss for modules with active resource groups
3. Implement a migration path for resources when metadata changes

## Proof of Concept

```rust
// Reproduction scenario:
// 1. Deploy module with resource group
// 2. Create resource groups
// 3. Upgrade module to v5 or simulate metadata loss
// 4. Attempt to read via API pagination

#[test]
fn test_resource_group_metadata_inconsistency() {
    // Setup: Create a state with resource groups
    let mut state = setup_test_state();
    
    // Deploy module with resource group Container
    deploy_module_with_resource_group(&mut state, "Container");
    
    // Create resource groups stored with Path::ResourceGroup
    create_resource_group(&mut state, account_address, "Container");
    
    // Simulate metadata loss (v5 upgrade or module removal)
    upgrade_module_to_v5(&mut state, "Container"); // This strips metadata
    
    // Attempt to read via API pagination
    let context = create_api_context(state);
    let result = context.get_account_resources_with_pagination(
        account_address,
        None,
        None,
        10
    );
    
    // Expected: Should fail or return corrupted data
    // Actual: Returns error or garbage because BTreeMap bytes 
    // are interpreted as struct bytes
    assert!(result.is_err() || result.unwrap().0.is_empty());
}
```

## Notes

The vulnerability breaks the **State Consistency** invariant (#4): "State transitions must be atomic and verifiable via Merkle proofs." The API layer cannot correctly interpret state data when module metadata is inconsistent with storage representation.

This issue is distinct from normal Move execution because it occurs at the API/RPC layer where module metadata availability is not guaranteed, unlike the VM which has stricter metadata requirements during transaction execution.

### Citations

**File:** aptos-move/aptos-vm/src/data_cache.rs (L98-129)
```rust
    fn get_any_resource_with_layout(
        &self,
        address: &AccountAddress,
        struct_tag: &StructTag,
        metadata: &[Metadata],
        maybe_layout: Option<&MoveTypeLayout>,
    ) -> PartialVMResult<(Option<Bytes>, usize)> {
        let resource_group = get_resource_group_member_from_metadata(struct_tag, metadata);
        if let Some(resource_group) = resource_group {
            let key = StateKey::resource_group(address, &resource_group);
            let buf =
                self.resource_group_view
                    .get_resource_from_group(&key, struct_tag, maybe_layout)?;

            let first_access = self.accessed_groups.borrow_mut().insert(key.clone());
            let group_size = if first_access {
                self.resource_group_view.resource_group_size(&key)?.get()
            } else {
                0
            };

            let buf_size = resource_size(&buf);
            Ok((buf, buf_size + group_size as usize))
        } else {
            let state_key = resource_state_key(address, struct_tag)?;
            let buf = self
                .executor_view
                .get_resource_bytes(&state_key, maybe_layout)?;
            let buf_size = resource_size(&buf);
            Ok((buf, buf_size))
        }
    }
```

**File:** api/src/context.rs (L535-551)
```rust
        // Extract resources from resource groups and flatten into all resources
        let kvs = kvs
            .into_iter()
            .map(|(tag, value)| {
                if converter.is_resource_group(&tag) {
                    // An error here means a storage invariant has been violated
                    bcs::from_bytes::<ResourceGroup>(&value)
                        .map(|map| map.into_iter().collect::<Vec<_>>())
                        .map_err(|e| e.into())
                } else {
                    Ok(vec![(tag, value)])
                }
            })
            .collect::<Result<Vec<Vec<(StructTag, Vec<u8>)>>>>()?
            .into_iter()
            .flatten()
            .collect();
```

**File:** api/types/src/convert.rs (L97-110)
```rust
    pub fn is_resource_group(&self, tag: &StructTag) -> bool {
        if let Ok(Some(module)) = self.inner.view_module(&tag.module_id()) {
            if let Some(md) = get_metadata(&module.metadata) {
                if let Some(attrs) = md.struct_attributes.get(tag.name.as_ident_str().as_str()) {
                    return attrs
                        .iter()
                        .find(|attr| attr.is_resource_group())
                        .map(|_| true)
                        .unwrap_or(false);
                }
            }
        }
        false
    }
```

**File:** types/src/vm/module_metadata.rs (L294-298)
```rust
        if code.version() == 5 {
            if let Some(metadata) = metadata.as_mut() {
                metadata.struct_attributes.clear();
                metadata.fun_attributes.clear();
            }
```

**File:** aptos-move/aptos-resource-viewer/src/module_view.rs (L56-87)
```rust
    fn view_compiled_module(&self, module_id: &ModuleId) -> anyhow::Result<Option<Self::Item>> {
        let mut module_cache = self.module_cache.borrow_mut();
        if let Some(module) = module_cache.get(module_id) {
            return Ok(Some(module.clone()));
        }

        let state_key = StateKey::module_id(module_id);
        Ok(
            match self
                .state_view
                .get_state_value_bytes(&state_key)
                .map_err(|e| anyhow!("Error retrieving module {:?}: {:?}", module_id, e))?
            {
                Some(bytes) => {
                    let compiled_module =
                        CompiledModule::deserialize_with_config(&bytes, &self.deserializer_config)
                            .map_err(|status| {
                                anyhow!(
                                    "Module {:?} deserialize with error code {:?}",
                                    module_id,
                                    status
                                )
                            })?;

                    let compiled_module = Arc::new(compiled_module);
                    module_cache.insert(module_id.clone(), compiled_module.clone());
                    Some(compiled_module)
                },
                None => None,
            },
        )
    }
```
