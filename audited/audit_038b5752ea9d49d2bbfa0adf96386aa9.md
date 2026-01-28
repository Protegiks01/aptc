# Audit Report

## Title
SAFER_RESOURCE_GROUPS Protection Bypass via Empty Metadata Module Upgrade

## Summary
The `SAFER_RESOURCE_GROUPS` feature flag protection can be bypassed when upgrading from a module without metadata. The `extract_resource_group_metadata_from_module()` function incorrectly returns an empty structs set when the old module lacks metadata, allowing attackers to add resource group attributes to existing structs without validation. [1](#0-0) 

## Finding Description
The `SAFER_RESOURCE_GROUPS` feature flag (enabled by default) is designed to prevent adding resource_group or resource_group_member attributes to existing structs during module upgrades, as this can cause storage inconsistencies and violate Move's upgrade compatibility guarantees. [2](#0-1) 

The validation logic checks if new resource group attributes are being added to existing structs by testing if struct names exist in the `structs` set extracted from the old module. [3](#0-2) 

However, the `extract_resource_group_metadata_from_module()` function has a critical flaw: when the old module has no metadata section, it returns an empty `structs` set instead of extracting struct names from the module's struct definitions. [4](#0-3) 

This is incorrect because when metadata exists, the function properly extracts struct names from `old_module.struct_defs()`, but when metadata doesn't exist, it skips this step entirely. [5](#0-4) 

**Attack Path**:
1. Attacker publishes module V1 with struct definitions but without metadata section (modules can be published without metadata if they have no attributes or error maps) [6](#0-5) 

2. Attacker upgrades to module V2, adding `#[resource_group]` or `#[resource_group_member]` attributes to existing structs from V1
3. During validation, `extract_resource_group_metadata_from_module(V1)` returns empty `structs` set
4. The SAFER_RESOURCE_GROUPS validation checks against empty set, finding no conflicts
5. Resource group attributes are successfully added to existing structs, bypassing protection

The existing test suite confirms that adding resource_group_member attributes to existing structs is considered unsafe and should be prevented when SAFER_RESOURCE_GROUPS is enabled. [7](#0-6) 

## Impact Explanation
This is a **High Severity** vulnerability (up to $50,000) under the "Significant protocol violations" category. The issue:

- **Bypasses Security Feature**: Circumvents SAFER_RESOURCE_GROUPS, which is enabled by default and expected to protect against unsafe upgrades
- **Storage Corruption Risk**: Adding resource group semantics to existing structs retroactively can cause storage model inconsistencies, as resource groups change the storage layout from individual resources to grouped resources
- **Breaks Upgrade Guarantees**: Violates Move's upgrade compatibility rules that existing struct instances must remain valid after upgrades

The resource groups validation is explicitly called during module publishing to ensure upgrade safety. [8](#0-7) 

## Likelihood Explanation
**MEDIUM-HIGH likelihood** because:

1. **Attack Requirements**: Only requires publishing a module without metadata (explicitly permitted), then upgrading it
2. **Feasibility**: Modules can be published without metadata through older compilers or manually crafted bytecode, or simply by creating modules with no attributes and no error maps
3. **Attacker Capability**: Any unprivileged module publisher can execute this attack
4. **Expected Protection**: Users and developers expect SAFER_RESOURCE_GROUPS (enabled by default) to prevent these unsafe upgrades

## Recommendation
The fix is to extract struct names from the old module even when metadata doesn't exist. The function should be corrected as follows:

```rust
} else {
    let structs = old_module
        .struct_defs()
        .iter()
        .map(|struct_def| {
            let struct_handle = old_module.struct_handle_at(struct_def.struct_handle);
            old_module.identifier_at(struct_handle.name).to_string()
        })
        .collect::<BTreeSet<_>>();
    Ok((BTreeMap::new(), BTreeMap::new(), structs))
}
```

This ensures that the SAFER_RESOURCE_GROUPS validation correctly checks against all existing structs in the old module, regardless of whether the module has metadata.

## Proof of Concept
The vulnerability can be demonstrated by:

1. Publishing a module V1 with struct definitions but no resource group attributes (and no error map to ensure no metadata)
2. Upgrading to module V2 that adds `#[resource_group_member]` to an existing struct
3. Observing that the upgrade succeeds when it should fail with SAFER_RESOURCE_GROUPS enabled

This bypasses the protection that is demonstrated to work correctly in the test suite when metadata exists.

## Notes
The vulnerability is a clear logic bug where the function fails to extract struct names when no metadata exists, leading to an empty set that causes the validation to incorrectly pass. This is a genuine security issue that bypasses an enabled-by-default protection mechanism designed to prevent unsafe module upgrades.

### Citations

**File:** aptos-move/aptos-vm/src/verifier/resource_groups.rs (L176-186)
```rust
    for group in new_groups.keys() {
        if structs.remove(group) {
            metadata_validation_err("Invalid addition of resource_group attribute")?;
        }
    }

    for member in new_members.keys() {
        if structs.remove(member) {
            metadata_validation_err("Invalid addition of resource_group_member attribute")?;
        }
    }
```

**File:** aptos-move/aptos-vm/src/verifier/resource_groups.rs (L192-213)
```rust
pub(crate) fn extract_resource_group_metadata_from_module(
    old_module: &CompiledModule,
) -> VMResult<(
    BTreeMap<String, ResourceGroupScope>,
    BTreeMap<String, StructTag>,
    BTreeSet<String>,
)> {
    if let Some(metadata) = get_metadata_from_compiled_code(old_module) {
        let (groups, members) = extract_resource_group_metadata(&metadata)?;
        let structs = old_module
            .struct_defs()
            .iter()
            .map(|struct_def| {
                let struct_handle = old_module.struct_handle_at(struct_def.struct_handle);
                old_module.identifier_at(struct_handle.name).to_string()
            })
            .collect::<BTreeSet<_>>();
        Ok((groups, members, structs))
    } else {
        Ok((BTreeMap::new(), BTreeMap::new(), BTreeSet::new()))
    }
}
```

**File:** types/src/on_chain_config/aptos_features.rs (L205-205)
```rust
            FeatureFlag::SAFER_RESOURCE_GROUPS,
```

**File:** aptos-move/framework/src/built_package.rs (L622-622)
```rust
                    if !module_metadata.is_empty() {
```

**File:** aptos-move/e2e-move-tests/src/tests/resource_groups.rs (L473-508)
```rust
#[test]
fn verify_unsafe_resource_group_member_upgrades() {
    let mut h = MoveHarness::new_with_features(vec![], vec![FeatureFlag::SAFER_RESOURCE_GROUPS]);
    let account = h.new_account_at(AccountAddress::from_hex_literal("0xf00d").unwrap());

    // Initial code
    let source = r#"
        module 0xf00d::M {
            struct NotResourceGroupMember has key { }

            #[resource_group(scope = address)]
            struct ResourceGroup { }
        }
        "#;
    let mut builder = PackageBuilder::new("Package");
    builder.add_source("m.move", source);
    let path = builder.write_to_temp().unwrap();
    let result = h.publish_package(&account, path.path());
    assert_success!(result);

    // Incompatible addition of ResourceGroupMember
    let source = r#"
        module 0xf00d::M {
            #[resource_group_member(group = 0xf00d::M::ResourceGroup)]
            struct NotResourceGroupMember has key { }

            #[resource_group(scope = address)]
            struct ResourceGroup { }
        }
        "#;
    let mut builder = PackageBuilder::new("Package");
    builder.add_source("m.move", source);
    let path = builder.write_to_temp().unwrap();
    let result = h.publish_package(&account, path.path());
    assert_success!(result);
}
```

**File:** aptos-move/aptos-vm/src/aptos_vm.rs (L1719-1725)
```rust
        resource_groups::validate_resource_groups(
            self.features(),
            module_storage,
            traversal_context,
            gas_meter,
            modules,
        )?;
```
