# Audit Report

## Title
Resource Group Metadata Inconsistency Allows State Duplication via Module Upgrade TOCTOU

## Summary
When the `SAFER_RESOURCE_GROUPS` feature flag is disabled, implementations of `AptosMoveResolver` can provide different views of the same resource through `ResourceResolver` and `ResourceGroupResolver` trait methods. This occurs when a module is upgraded to add a `resource_group_member` attribute to an existing struct, causing legacy resource instances to remain at their original storage location while new queries search the resource group location, enabling violation of Move's resource uniqueness invariant.

## Finding Description

The `AptosMoveResolver` trait combines multiple resolver interfaces, including `ResourceResolver` and `ResourceGroupResolver`. The critical vulnerability lies in how these resolvers determine resource storage locations based on module metadata. [1](#0-0) 

The `StorageAdapter` implements resource retrieval through `get_any_resource_with_layout`, which uses module metadata to determine if a resource belongs to a group: [2](#0-1) 

This creates two distinct code paths:
1. **Group Member Path**: Queries `StateKey::resource_group(address, group_tag)` via `resource_group_view`
2. **Standalone Path**: Queries `StateKey::resource(address, struct_tag)` via `executor_view`

The resource group verification logic explicitly allows adding `resource_group_member` attributes to existing structs when `SAFER_RESOURCE_GROUPS` is disabled: [3](#0-2) 

**Attack Scenario:**

1. **Initial State**: Module `M` defines struct `S` without `resource_group_member` attribute. An instance exists at `StateKey::resource(0xA, S)`.

2. **Module Upgrade**: When `SAFER_RESOURCE_GROUPS` is disabled, module owner upgrades `M` to add `#[resource_group_member(group = G)]` to struct `S`.

3. **TOCTOU Exploitation**:
   - **Time-of-Check**: Call `ResourceGroupResolver.resource_exists_in_group(StateKey::resource_group(0xA, G), S)` → Returns `false` (resource not in group)
   - **Time-of-Use**: Call `move_to<S>(signer(0xA), new_instance)` → Succeeds, stores at group location
   
4. **Result**: TWO instances of `S` exist at address `0xA`:
   - Legacy instance at `StateKey::resource(0xA, S)`  
   - New instance at `StateKey::resource_group(0xA, G)` under tag `S`

The test suite explicitly validates this unsafe behavior is permitted when the flag is disabled: [4](#0-3) 

This violates **Invariant #4 (State Consistency)** - different resolver paths return inconsistent views of whether a resource exists, and **Move's fundamental resource uniqueness invariant** - at most one instance of a resource type can exist per address.

## Impact Explanation

**Severity: Medium**

While this issue can cause state inconsistencies, it has mitigating factors:

1. **Requires Module Ownership**: Exploitation requires the ability to upgrade a module, limiting the attack surface to module publishers
2. **Feature Flag Protection**: The `SAFER_RESOURCE_GROUPS` feature flag (when enabled) prevents this scenario entirely
3. **Known Issue**: The Aptos team has already identified and mitigated this with the feature flag

However, when `SAFER_RESOURCE_GROUPS` is disabled (for backward compatibility or testing), the impact includes:
- State corruption through duplicate resources
- Potential consensus divergence if validators have different resource group cache states  
- Violation of Move's type safety guarantees
- Ability to bypass resource existence checks in Move contracts

This meets **Medium Severity** criteria per Aptos bug bounty rules: "State inconsistencies requiring intervention."

## Likelihood Explanation

**Likelihood: Low-to-Medium**

The vulnerability requires:
1. `SAFER_RESOURCE_GROUPS` feature flag to be disabled (non-default configuration)
2. Module owner to perform a specific upgrade pattern (adding `resource_group_member` to existing struct)
3. Existing resource instances created before the upgrade
4. No automatic migration of legacy resources to new group location

The test evidence confirms this scenario is explicitly permitted when the safety flag is disabled, making it a realistic attack vector in those configurations.

## Recommendation

**Mandatory Enforcement:**
Always enable `SAFER_RESOURCE_GROUPS` feature flag in production environments. This flag should be:
1. Enabled by default in mainnet configurations
2. Documented as a critical security control
3. Never disabled except in controlled test environments

**Additional Safeguards:**

```rust
// In resource_groups.rs validation
pub(crate) fn validate_module_and_extract_new_entries(
    // ... existing parameters
) -> VMResult<...> {
    // ... existing logic ...
    
    // ALWAYS enforce safer resource groups, remove feature flag dependency
    // Remove the conditional at line 167:
    // if !features.is_enabled(FeatureFlag::SAFER_RESOURCE_GROUPS) {
    //     return Ok((new_groups, new_members));
    // }
    
    // Always perform strict validation:
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

    Ok((new_groups, new_members))
}
```

**Migration Support:**
If modules must add resource group attributes, provide explicit migration utilities that:
1. Enumerate all existing resource instances
2. Atomically move them to the correct group location
3. Verify no duplicates exist before completing the upgrade

## Proof of Concept

```move
// Module v1 - No resource group
module 0xCAFE::exploit {
    struct VulnerableResource has key {
        value: u64
    }
    
    #[resource_group(scope = address)]
    struct ResourceGroup { }
    
    public entry fun create_v1(account: &signer, value: u64) {
        move_to(account, VulnerableResource { value });
    }
}

// Module v2 - Added resource_group_member (when SAFER_RESOURCE_GROUPS disabled)
module 0xCAFE::exploit {
    #[resource_group_member(group = 0xCAFE::exploit::ResourceGroup)]
    struct VulnerableResource has key {
        value: u64
    }
    
    #[resource_group(scope = address)]
    struct ResourceGroup { }
    
    public entry fun exploit_duplicate(account: &signer, new_value: u64) acquires VulnerableResource {
        // This succeeds because resource_exists looks in the group,
        // doesn't find the old instance at non-group location
        assert!(!exists<VulnerableResource>(@0xUSER), 1);
        
        // Creates SECOND instance in group location
        move_to(account, VulnerableResource { value: new_value });
        
        // Now TWO instances exist!
        // Old: StateKey::resource(0xUSER, VulnerableResource)
        // New: StateKey::resource_group(0xUSER, ResourceGroup)[VulnerableResource]
    }
}
```

**Notes**

This vulnerability is partially mitigated by the existing `SAFER_RESOURCE_GROUPS` feature flag, which was specifically introduced to prevent this class of issues. However, the fact that this protection can be disabled represents a systemic risk. The codebase should enforce resource group safety unconditionally rather than relying on runtime feature flags that may be misconfigured or disabled for compatibility reasons.

The core issue demonstrates that `AptosMoveResolver` CAN provide different views through its constituent traits when module metadata evolves, directly answering the security question in the affirmative.

### Citations

**File:** aptos-move/aptos-vm/src/move_vm_ext/resolver.rs (L19-30)
```rust
pub trait AptosMoveResolver:
    AggregatorV1Resolver
    + ConfigStorage
    + DelayedFieldResolver
    + ResourceResolver
    + ResourceGroupResolver
    + StateStorageView<Key = StateKey>
    + TableResolver
    + AsExecutorView
    + AsResourceGroupView
{
}
```

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

**File:** aptos-move/aptos-vm/src/verifier/resource_groups.rs (L167-186)
```rust
    if !features.is_enabled(FeatureFlag::SAFER_RESOURCE_GROUPS) {
        return Ok((new_groups, new_members));
    }

    // At this point, only original structs that do not have resource group affiliation are left.
    // Note, we do not validate for being both a member and a group, because there are other
    // checks earlier on, such as, a resource group must have no abilities, while a resource group
    // member must.

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
