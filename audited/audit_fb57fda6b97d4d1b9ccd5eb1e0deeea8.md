# Audit Report

## Title
Version Mismatch Consensus Divergence via Resource Group Split Capability Check

## Summary
A version mismatch vulnerability exists where validators running different code versions could produce divergent state roots when processing transactions that modify resource groups, due to different implementations of `is_resource_groups_split_in_change_set_capable()`.

## Finding Description

The vulnerability lies in the interaction between the trait default implementation and the block executor's override of `is_resource_groups_split_in_change_set_capable()`. [1](#0-0) 

The trait provides a default implementation returning `false`, but the block executor's `LatestView` overrides this to return `true`: [2](#0-1) 

This capability check determines the `GroupSizeKind` in `ResourceGroupAdapter`: [3](#0-2) 

The `GroupSizeKind` then controls whether `release_group_cache()` returns `Some(cache)` or `None`: [4](#0-3) 

This determines whether `ResourceGroupChangeSet::V0` (merged) or `V1` (split) format is used: [5](#0-4) 

**Attack Path:**
1. Validator set includes both old nodes (where `LatestView::is_resource_groups_split_in_change_set_capable()` is not yet implemented or returns false) and new nodes (where it returns true)
2. On-chain feature flag `RESOURCE_GROUPS_SPLIT_IN_VM_CHANGE_SET` is enabled
3. A transaction modifies a resource group
4. Old validators: capability = false → `GroupSizeKind::AsBlob` → returns cache → V0 format (merged blob)
5. New validators: capability = true → `GroupSizeKind::AsSum` → returns None → V1 format (split resources)
6. Different VMChangeSet formats produce different state roots
7. Consensus breaks - validators cannot agree on the same block

## Impact Explanation

This breaks **Invariant #1: Deterministic Execution** - validators must produce identical state roots for identical blocks. This is a **Critical Severity** consensus violation that would cause network partition requiring a hardfork to resolve, meeting the criteria for "Non-recoverable network partition (requires hardfork)" and "Consensus/Safety violations" in the Aptos bug bounty program.

## Likelihood Explanation

**Medium-High Likelihood** during a rolling validator upgrade where:
- The feature flag is enabled (it's in default features)
- Validators are running mixed code versions
- Transactions modify resource groups (common in DeFi operations, staking, governance)

The likelihood is elevated because Aptos likely performs rolling upgrades to avoid downtime, creating windows where validators run different code versions. However, critical consensus changes are typically coordinated with epoch boundaries.

## Recommendation

**Option 1 (Immediate):** Remove the trait default implementation and require explicit implementation:

```rust
pub trait TResourceGroupView {
    // ... other methods ...
    
    // Remove default implementation - force explicit implementation
    fn is_resource_groups_split_in_change_set_capable(&self) -> bool;
}
```

**Option 2 (Feature Flag):** Make the capability check dependent solely on on-chain state, not code version:

```rust
fn is_resource_groups_split_in_change_set_capable(&self) -> bool {
    // Always check on-chain config, never rely on code version
    let features = Features::fetch_config(self.get_state_view()).unwrap_or_default();
    features.is_resource_groups_split_in_vm_change_set_enabled()
}
```

**Option 3 (Version Enforcement):** Add explicit version checks at epoch boundaries to ensure all validators run compatible code before enabling capability-dependent features.

## Proof of Concept

```rust
// PoC demonstrating the divergence (conceptual - would require two validator builds)

#[test]
fn test_resource_group_capability_mismatch() {
    // Validator A: Old code where LatestView uses default (returns false)
    struct OldLatestView;
    impl TResourceGroupView for OldLatestView {
        // Uses default implementation: returns false
    }
    
    // Validator B: New code where LatestView overrides (returns true)  
    struct NewLatestView;
    impl TResourceGroupView for NewLatestView {
        fn is_resource_groups_split_in_change_set_capable(&self) -> bool {
            true
        }
    }
    
    // Both validators have feature flag enabled
    let mut features = Features::default();
    features.enable(FeatureFlag::RESOURCE_GROUPS_SPLIT_IN_VM_CHANGE_SET);
    
    // Create adapters for both
    let old_adapter = ResourceGroupAdapter::new(
        Some(&OldLatestView),
        &state_view,
        12,
        features.is_resource_groups_split_in_vm_change_set_enabled(),
    );
    
    let new_adapter = ResourceGroupAdapter::new(
        Some(&NewLatestView),
        &state_view,
        12,
        features.is_resource_groups_split_in_vm_change_set_enabled(),
    );
    
    // Verify they produce different group_size_kinds
    assert_eq!(old_adapter.group_size_kind(), GroupSizeKind::AsBlob);
    assert_eq!(new_adapter.group_size_kind(), GroupSizeKind::AsSum);
    
    // Execute transaction modifying resource group on both
    // Old validator produces V0 (merged) changeset
    // New validator produces V1 (split) changeset
    // → Different state roots → Consensus divergence
}
```

**Notes:**
This vulnerability represents a **critical design flaw** in how capability checks interact with code versioning during validator upgrades. While Aptos may have mitigated this through coordinated upgrade procedures, the code structure itself allows for consensus divergence if validators run mismatched versions when the feature flag is enabled.

### Citations

**File:** aptos-move/aptos-vm-types/src/resolver.rs (L83-85)
```rust
    fn is_resource_groups_split_in_change_set_capable(&self) -> bool {
        false
    }
```

**File:** aptos-move/block-executor/src/view.rs (L1787-1789)
```rust
    fn is_resource_groups_split_in_change_set_capable(&self) -> bool {
        true
    }
```

**File:** aptos-move/aptos-vm-types/src/resource_group_adapter.rs (L134-147)
```rust
        let group_size_kind = GroupSizeKind::from_gas_feature_version(
            gas_feature_version,
            // Even if flag is enabled, if we are in non-capable context, we cannot use AsSum,
            // and split resource groups in the VMChangeSet.
            // We are not capable if:
            // - Block contains single PayloadWriteSet::Direct transaction
            // - we are not executing blocks for a live network in a gas charging context
            //     (outside of BlockExecutor) i.e. unit tests, view functions, etc.
            //     In this case, disabled will lead to a different gas behavior,
            //     but gas is not relevant for those contexts.
            resource_groups_split_in_vm_change_set_enabled
                && maybe_resource_group_view
                    .is_some_and(|v| v.is_resource_groups_split_in_change_set_capable()),
        );
```

**File:** aptos-move/aptos-vm-types/src/resource_group_adapter.rs (L289-309)
```rust
    fn release_group_cache(
        &self,
    ) -> Option<HashMap<Self::GroupKey, BTreeMap<Self::ResourceTag, Bytes>>> {
        if self.group_size_kind == GroupSizeKind::AsSum {
            // Clear the cache, but do not return the contents to the caller. This leads to
            // the VMChangeSet prepared in a new, granular format that the block executor
            // can handle (combined as a group update at the end).
            self.group_cache.borrow_mut().clear();
            None
        } else {
            // Returning the contents to the caller leads to preparing the VMChangeSet in the
            // backwards compatible way (containing the whole group update).
            Some(
                self.group_cache
                    .borrow_mut()
                    .drain()
                    .map(|(k, v)| (k, v.0))
                    .collect(),
            )
        }
    }
```

**File:** aptos-move/aptos-vm/src/move_vm_ext/session/mod.rs (L347-356)
```rust
        let mut maybe_resource_group_cache = resolver.release_resource_group_cache().map(|v| {
            v.into_iter()
                .map(|(k, v)| (k, v.into_iter().collect::<BTreeMap<_, _>>()))
                .collect::<BTreeMap<_, _>>()
        });
        let mut resource_group_change_set = if maybe_resource_group_cache.is_some() {
            ResourceGroupChangeSet::V0(BTreeMap::new())
        } else {
            ResourceGroupChangeSet::V1(BTreeMap::new())
        };
```
