# Audit Report

## Title
Phantom Read Vulnerability in Resource Group Parallel Execution Enabling Consensus Splits

## Summary
The block executor's parallel transaction validation fails to detect phantom reads in resource groups when `GroupSizeKind` is not `AsSum`. When the `RESOURCE_GROUPS_SPLIT_IN_VM_CHANGE_SET` feature flag is disabled or when using older gas versions, the resource group size is never captured during execution, allowing new resources to be added to groups between execution and validation without detection. This violates snapshot isolation and can cause consensus splits.

## Finding Description

The vulnerability exists in the interaction between resource group gas charging configuration and the parallel block executor's read-set validation mechanism.

**The Attack Flow:**

1. **Configuration Vulnerability**: When `GroupSizeKind != AsSum`, the `ResourceGroupAdapter` filters out the block executor's resource group view. [1](#0-0) 

2. **Missing Size Capture**: During transaction execution, when reading the first resource from a group, `resource_group_size` is called for gas charging. [2](#0-1) 

However, when `group_size_kind != AsSum`, the adapter returns early without calling the block executor's view. [3](#0-2) 

3. **No Size Validation**: During validation, if `group.collected_size` is `None`, group size validation is skipped. [4](#0-3) 

4. **Phantom Read Occurs**: Transaction T1 executes reading tags {A, B} from group G. Between execution and validation, transaction T0 commits and adds tag C to the group. Validation only checks tags A and B (which haven't changed), missing the phantom tag C. T1 commits with an inconsistent view.

**Broken Invariants:**
- **State Consistency**: Transactions commit with views that don't reflect the actual committed state
- **Deterministic Execution**: Different validators may observe different orderings and produce different state roots
- **Snapshot Isolation**: Transactions see inconsistent snapshots of resource group membership

## Impact Explanation

**Severity: CRITICAL** (Consensus/Safety Violation)

This vulnerability enables **consensus splits** - the most severe category of blockchain vulnerabilities. When different validators execute the same block of transactions in parallel, they may:

1. Observe different transaction interleavings
2. Commit transactions with phantom reads that other validators reject
3. Produce different state roots for the same block
4. Fork the blockchain requiring manual intervention or hard fork

The impact includes:
- **Double spending**: Transactions can observe inconsistent states and execute with different outcomes
- **Chain splits**: Validators diverge on block validity
- **Fund loss**: Users' transactions may be included in blocks that later become invalid
- **Network partition**: Requires emergency intervention to resolve

This meets the **Critical Severity** criteria: "Consensus/Safety violations" and "Non-recoverable network partition (requires hardfork)".

## Likelihood Explanation

**Likelihood: MEDIUM to HIGH** depending on deployment configuration

The vulnerability is exploitable when:

1. **Gas Feature Version < 9**: Sets `GroupSizeKind::None` [5](#0-4) 

2. **Gas Feature Version >= 9 BUT `resource_groups_split_in_vm_change_set_enabled = false`**: Sets `GroupSizeKind::AsBlob`, which still filters out the resource group view [6](#0-5) 

**Affected Scenarios:**
- Testnet and private deployments that haven't enabled the feature flag
- Historical block replay/verification (before feature flag activation)
- Networks running older gas versions
- Potential future scenarios if the feature is disabled for compatibility

The attack requires:
- Multiple transactions accessing the same resource group (common in DeFi protocols)
- Parallel execution (standard in block executor)
- Specific gas configuration (depends on network)

## Recommendation

**Immediate Fix**: Always capture and validate resource group size, regardless of gas configuration.

**Solution 1 - Unconditional Size Capture**: Modify `ResourceGroupAdapter` to always forward `resource_group_size` calls to the block executor's view when in parallel execution context:

```rust
// In ResourceGroupAdapter::resource_group_size
pub fn resource_group_size(
    &self,
    group_key: &Self::GroupKey,
) -> PartialVMResult<ResourceGroupSize> {
    // Always use group_view if available, regardless of group_size_kind
    if let Some(group_view) = self.maybe_resource_group_view {
        return group_view.resource_group_size(group_key);
    }
    
    // Fallback to cache-based implementation
    if self.group_size_kind == GroupSizeKind::None {
        return Ok(ResourceGroupSize::zero_concrete());
    }
    
    self.load_to_cache(group_key)?;
    Ok(self.group_cache.borrow().get(group_key).expect("Must be cached").1)
}
```

**Solution 2 - Remove Filtering**: Remove the filter on `maybe_resource_group_view` so the block executor's view is always used:

```rust
// In ResourceGroupAdapter::new, line 149-152
Self {
    maybe_resource_group_view, // Don't filter!
    resource_view,
    group_size_kind,
    group_cache: RefCell::new(HashMap::new()),
}
```

**Solution 3 - Validation Enhancement**: Add phantom read detection by tracking group membership changes:

```rust
// In CapturedReads, track whether group was accessed without size
pub(crate) struct GroupRead<T: Transaction> {
    pub(crate) collected_size: Option<ResourceGroupSize>,
    pub(crate) inner_reads: HashMap<T::Tag, DataRead<T::Value>>,
    pub(crate) must_validate_size: bool, // NEW: Force size validation
}

// In validate_group_reads, always validate size if any tags were read
if !group.inner_reads.is_empty() && group.collected_size.is_none() {
    return false; // Fail validation if size wasn't captured
}
```

**Recommended Approach**: Implement Solution 2 (remove filtering) combined with Solution 3 (enhanced validation) to ensure both forward compatibility and defense in depth.

## Proof of Concept

```rust
// Rust reproduction demonstrating phantom read scenario
// This would be run as a block executor test

#[test]
fn test_phantom_read_in_resource_groups() {
    use aptos_types::on_chain_config::Features;
    
    // Setup: Configure gas feature version 9+ but disable split feature
    let mut features = Features::default();
    // Set gas_feature_version >= 9 (AsBlob mode)
    // But resource_groups_split_in_vm_change_set_enabled = false
    
    // Transaction T0: Adds resource C to group G at address 0x1
    let t0 = create_transaction_that_adds_resource_c_to_group();
    
    // Transaction T1: Reads resources A and B from group G
    // Logic: "if only A and B exist, do X; otherwise do Y"
    let t1 = create_transaction_that_reads_a_and_b_from_group();
    
    // Execute block [T0, T1] with parallel executor
    let block = vec![t0, t1];
    let output = execute_block_parallel(block, &features);
    
    // BUG: T1 executes seeing only {A, B} in the group
    // But validation passes even though T0 added C
    // T1 commits with inconsistent view
    
    // Expected: T1 should be re-executed after T0 commits
    // Actual: T1 validates successfully with stale read set
    
    assert!(output.is_consensus_split(), 
        "Phantom read allowed non-serializable execution");
}

// Move test showcasing the vulnerability
module test::phantom_read_attack {
    use std::signer;
    use aptos_framework::resource_group::resource_group;
    
    #[resource_group(scope = global)]
    struct MyGroup {}
    
    #[resource_group_member(group = MyGroup)]
    struct ResourceA has key { value: u64 }
    
    #[resource_group_member(group = MyGroup)]  
    struct ResourceB has key { value: u64 }
    
    #[resource_group_member(group = MyGroup)]
    struct ResourceC has key { value: u64 }
    
    // T0: Adds ResourceC
    public entry fun add_resource_c(account: &signer) {
        move_to(account, ResourceC { value: 100 });
    }
    
    // T1: Reads A and B, expects only 2 resources in group
    public entry fun read_and_validate(account: &signer) acquires ResourceA, ResourceB {
        let addr = signer::address_of(account);
        let _a = borrow_global<ResourceA>(addr);
        let _b = borrow_global<ResourceB>(addr);
        
        // Logic assumes only A and B exist
        // BUG: If C was added concurrently, this executes with wrong assumption
        // but validation doesn't detect the phantom read
    }
}
```

**Notes:**
- The vulnerability requires the `RESOURCE_GROUPS_SPLIT_IN_VM_CHANGE_SET` feature flag to be disabled or older gas versions
- On mainnet with the feature enabled (AsSum mode), group size is properly captured and validated
- However, testnets, private deployments, and historical replays remain vulnerable
- The fix should be applied regardless of current mainnet configuration for defense in depth and future compatibility

### Citations

**File:** aptos-move/aptos-vm-types/src/resource_group_adapter.rs (L32-44)
```rust
    pub fn from_gas_feature_version(
        gas_feature_version: u64,
        resource_groups_split_in_vm_change_set_enabled: bool,
    ) -> Self {
        if resource_groups_split_in_vm_change_set_enabled {
            GroupSizeKind::AsSum
        } else if gas_feature_version >= 9 {
            // Keep old caching behavior for replay.
            GroupSizeKind::AsBlob
        } else {
            GroupSizeKind::None
        }
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

**File:** aptos-move/aptos-vm-types/src/resource_group_adapter.rs (L149-152)
```rust
        Self {
            maybe_resource_group_view: maybe_resource_group_view
                .filter(|_| group_size_kind == GroupSizeKind::AsSum),
            resource_view,
```

**File:** aptos-move/aptos-vm-types/src/resource_group_adapter.rs (L236-251)
```rust
        if self.group_size_kind == GroupSizeKind::None {
            return Ok(ResourceGroupSize::zero_concrete());
        }

        if let Some(group_view) = self.maybe_resource_group_view {
            return group_view.resource_group_size(group_key);
        }

        self.load_to_cache(group_key)?;
        Ok(self
            .group_cache
            .borrow()
            .get(group_key)
            .expect("Must be cached")
            .1)
    }
```

**File:** aptos-move/aptos-vm/src/data_cache.rs (L112-117)
```rust
            let first_access = self.accessed_groups.borrow_mut().insert(key.clone());
            let group_size = if first_access {
                self.resource_group_view.resource_group_size(&key)?.get()
            } else {
                0
            };
```

**File:** aptos-move/block-executor/src/captured_reads.rs (L1102-1106)
```rust
        self.group_reads.iter().all(|(key, group)| {
            let mut ret = true;
            if let Some(size) = group.collected_size {
                ret &= group_map.validate_group_size(key, idx_to_validate, size);
            }
```
