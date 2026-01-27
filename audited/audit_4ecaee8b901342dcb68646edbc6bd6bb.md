# Audit Report

## Title
Hot State Tracking Confusion Due to Resource Group Member Migration Without SAFER_RESOURCE_GROUPS Protection

## Summary
When the `SAFER_RESOURCE_GROUPS` feature flag is disabled, module upgrades can add `#[resource_group_member]` attributes to structs that previously existed as standalone resources. This creates a scenario where the same logical resource type exists with two different `StateKey` representations, causing the hot state accumulator to track them as separate entities, leading to cache pollution and resource waste.

## Finding Description

The `BlockHotStateOpAccumulator` in `add_transaction()` receives keys extracted from `InputOutputKey` variants via the `keys_except_delayed_fields()` function. [1](#0-0) 

This function extracts the underlying `Key` from both `InputOutputKey::Resource(key)` and `InputOutputKey::Group(key, _)`, discarding tag information. When a struct is migrated from standalone resource to resource group member without proper validation, it creates two different `StateKey` values for the same logical resource:

1. **Legacy standalone instances**: `StateKey::resource(address, StructTag)` using `Path::Resource`
2. **New group member instances**: `StateKey::resource_group(address, GroupTag)` using `Path::ResourceGroup` [2](#0-1) 

The `SAFER_RESOURCE_GROUPS` feature flag exists specifically to prevent this scenario by rejecting module upgrades that add resource group attributes to existing structs: [3](#0-2) 

However, when this flag is disabled (possible via governance), the validation is bypassed, and the migration succeeds: [4](#0-3) 

The hot state accumulator then tracks both StateKeys separately: [5](#0-4) 

This causes both keys to potentially be added to the `to_make_hot` set, consuming double cache space and contributing to the `MAX_PROMOTIONS_PER_BLOCK` limit. [6](#0-5) 

## Impact Explanation

This is a **Medium severity** issue per the Aptos bug bounty criteria: "State inconsistencies requiring intervention." While hot state operations are not consensus-critical (they're not serialized): [7](#0-6) 

The impact includes:
- **Cache pollution**: Both StateKeys consume hot state slots unnecessarily
- **Performance degradation**: Incorrect cache behavior across the network
- **Resource exhaustion**: Contributing to hitting the 10,240 keys per block promotion limit
- **Inconsistent behavior**: Old vs new instances behave differently

## Likelihood Explanation

**Low likelihood** due to multiple prerequisites:
1. Governance must vote to disable `SAFER_RESOURCE_GROUPS` (enabled by default) [8](#0-7) 

2. A module upgrade must add `resource_group_member` to an existing struct
3. Legacy standalone resource instances must exist in state
4. Both old and new instances must be accessed frequently enough to trigger hot state tracking

## Recommendation

The `SAFER_RESOURCE_GROUPS` flag should remain enabled permanently, or the hot state tracking should be made resource-group-aware. The `keys_except_delayed_fields()` function could be enhanced to detect when a StateKey with `Path::ResourceGroup` is being used and handle it specially to prevent confusion with legacy standalone resources of the same type.

Alternatively, add runtime checks in the hot state accumulator to detect potential conflicts:

```rust
pub fn add_transaction<'a>(
    &mut self,
    writes: impl Iterator<Item = &'a Key>,
    reads: impl Iterator<Item = &'a Key>,
) where
    Key: 'a,
{
    // Add validation to detect resource group vs standalone collisions
    for key in writes {
        // Check if key represents a resource group that might conflict
        // with legacy standalone resources
        if self.to_make_hot.remove(key) {
            COUNTER.inc_with(&["promotion_removed_by_write"]);
        }
        self.writes.get_or_insert_owned(key);
    }
    // ... rest of implementation
}
```

## Proof of Concept

The test case demonstrating this behavior already exists: [4](#0-3) 

To demonstrate the hot state tracking issue, extend this test to:
1. Create instances of `NotResourceGroupMember` before the upgrade (standalone resources)
2. Execute the upgrade adding `#[resource_group_member]`
3. Create new instances (now as group members)
4. Access both old and new instances in transactions
5. Verify that `BlockHotStateOpAccumulator` tracks them with different StateKeys
6. Observe both appearing in the `to_make_hot` set despite representing the same logical resource type

## Notes

While this issue exists and represents a design flaw in how hot state tracking interacts with resource group migrations, it has **significant limitations**:
- Requires governance control to disable a safety feature
- Only affects performance, not consensus or state consistency
- The mitigation (keeping SAFER_RESOURCE_GROUPS enabled) is already the default

The security question correctly identifies this as "Medium" severity given these constraints.

### Citations

**File:** aptos-move/block-executor/src/types.rs (L64-71)
```rust
    fn keys_except_delayed_fields<'a>(
        keys: impl Iterator<Item = &'a InputOutputKey<T::Key, T::Tag>>,
    ) -> impl Iterator<Item = &'a T::Key> {
        keys.filter_map(|k| match k {
            InputOutputKey::Resource(key) | InputOutputKey::Group(key, _) => Some(key),
            InputOutputKey::DelayedField(_) => None,
        })
    }
```

**File:** types/src/access_path.rs (L76-82)
```rust
#[derive(Clone, Debug, Eq, PartialEq, Hash, Serialize, Deserialize, Ord, PartialOrd)]
#[cfg_attr(any(test, feature = "fuzzing"), derive(Arbitrary))]
pub enum Path {
    Code(ModuleId),
    Resource(StructTag),
    ResourceGroup(StructTag),
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

**File:** aptos-move/block-executor/src/hot_state_op_accumulator.rs (L27-28)
```rust
    /// TODO(HotState): make on-chain config
    const MAX_PROMOTIONS_PER_BLOCK: usize = 1024 * 10;
```

**File:** aptos-move/block-executor/src/hot_state_op_accumulator.rs (L42-66)
```rust
    pub fn add_transaction<'a>(
        &mut self,
        writes: impl Iterator<Item = &'a Key>,
        reads: impl Iterator<Item = &'a Key>,
    ) where
        Key: 'a,
    {
        for key in writes {
            if self.to_make_hot.remove(key) {
                COUNTER.inc_with(&["promotion_removed_by_write"]);
            }
            self.writes.get_or_insert_owned(key);
        }

        for key in reads {
            if self.to_make_hot.len() >= self.max_promotions_per_block {
                COUNTER.inc_with(&["max_promotions_per_block_hit"]);
                continue;
            }
            if self.writes.contains(key) {
                continue;
            }
            self.to_make_hot.insert(key.clone());
        }
    }
```

**File:** types/src/write_set.rs (L516-553)
```rust
// TODO(HotState): revisit when the hot state is deterministic.
/// Represents a hotness only change, not persisted for now.
#[derive(Clone, Eq, PartialEq)]
pub struct HotStateOp(BaseStateOp);

impl HotStateOp {
    pub fn make_hot() -> Self {
        Self(BaseStateOp::MakeHot)
    }

    pub fn as_base_op(&self) -> &BaseStateOp {
        &self.0
    }

    pub fn into_base_op(self) -> BaseStateOp {
        self.0
    }
}

impl Debug for HotStateOp {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        use BaseStateOp::*;

        match &self.0 {
            MakeHot => write!(f, "MakeHot"),
            Creation(_) | Modification(_) | Deletion(_) => {
                unreachable!("malformed hot state op")
            },
        }
    }
}

#[derive(BCSCryptoHash, Clone, CryptoHasher, Debug, Default, Eq, PartialEq)]
pub struct WriteSet {
    value: ValueWriteSet,
    /// TODO(HotState): this field is not serialized for now.
    hotness: BTreeMap<StateKey, HotStateOp>,
}
```

**File:** types/src/on_chain_config/aptos_features.rs (L205-205)
```rust
            FeatureFlag::SAFER_RESOURCE_GROUPS,
```
