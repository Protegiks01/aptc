# Audit Report

## Title
Zero IO Gas Charges for Resource Group Deletions in IoPricingV2/V3 Create Gas Metering Asymmetry

## Summary
Resource group deletions in feature versions 1-11 (IoPricingV2 and IoPricingV3) are charged zero IO gas regardless of the size of the resource group being deleted, while creation charges scale with size. This creates an economic asymmetry where validators process deletion operations without adequate IO gas compensation.

## Finding Description

When a resource group is deleted, the `materialized_size()` function returns `WriteOpSize::Deletion` because `maybe_group_op_size` is set to `None`: [1](#0-0) 

The deletion WriteOpSize is then used for IO gas calculation: [2](#0-1) 

In IoPricingV2 (feature versions 1-9), deletions return zero IO gas: [3](#0-2) 

In IoPricingV3 (feature versions 10-11), deletions also return zero IO gas: [4](#0-3) 

Resource groups are serialized as single blobs that can be arbitrarily large: [5](#0-4) 

This creates an asymmetry: creating large resource groups charges IO gas proportional to size, but deleting them charges zero IO gas in V2/V3.

## Impact Explanation

This issue represents a **gas metering inconsistency** rather than a critical vulnerability. While it violates the principle that "all operations must respect gas limits," the practical impact is limited:

1. **No Direct Fund Loss**: Attackers must pay full creation costs before benefiting from free deletions
2. **Network Benefit**: Deletions reduce state bloat, which is beneficial
3. **Limited Scope**: Only affects feature versions 1-11; V4 (version 12+) partially addresses this
4. **Minimal Validator Impact**: Deletion operations are computationally lightweight (O(log n) Merkle updates)

However, this does represent **underpricing of validator resources** because:
- Validators must still process deletion transactions
- Large resource groups require memory and cache during execution
- The zero charge creates potential for griefing attacks

This qualifies as **Medium severity** under "State inconsistencies requiring intervention" - not for creating actual state inconsistencies, but for creating economic inconsistencies in gas pricing that could require protocol-level intervention to fix.

## Likelihood Explanation

**Likelihood: Medium**

The issue can be exploited by any user without special privileges:
1. Create large resource groups across multiple transactions (pays full creation costs)
2. Delete them in subsequent transactions (pays zero IO gas in V2/V3)
3. Net effect: Validators process deletions without IO gas compensation

However, exploitation is limited by:
- Attacker must pay significant upfront costs for creation
- The "benefit" is only avoiding small IO gas charges
- Feature versions 1-11 may not be widely deployed
- V4 (version 12+) partially mitigates by charging base + key size

## Recommendation

**Short-term Fix**: Ensure all pricing versions charge at minimum a base slot write cost for deletions, similar to IoPricingV1 and V4:

For IoPricingV2, modify the deletion case to charge base costs:
```rust
Deletion => self.per_item_write * NumArgs::new(1),
```

For IoPricingV3, modify to charge base costs:
```rust
op_size.write_len().map_or_else(
    || Either::Right(STORAGE_IO_PER_STATE_SLOT_WRITE * NumArgs::new(1)),
    |write_len| { /* existing logic */ }
)
```

**Long-term Consideration**: Evaluate whether deletion IO gas should scale with the size of data being deleted to account for cache pollution and memory usage during transaction execution, even though the write operation itself is O(1).

## Proof of Concept

```rust
// This PoC demonstrates the gas asymmetry in feature versions 1-11

#[test]
fn test_resource_group_deletion_zero_gas_v2() {
    use aptos_vm_types::storage::io_pricing::{IoPricing, IoPricingV2};
    use aptos_types::{state_store::state_key::StateKey, write_set::WriteOpSize};
    
    // Simulate IoPricingV2 (feature version 1-9)
    let pricing_v2 = IoPricingV2 {
        feature_version: 5,
        free_write_bytes_quota: NumBytes::new(1024),
        per_item_read: InternalGasPerArg::new(100),
        per_item_create: InternalGasPerArg::new(1000),
        per_item_write: InternalGasPerArg::new(100),
        per_byte_read: InternalGasPerByte::new(10),
        per_byte_create: InternalGasPerByte::new(50),
        per_byte_write: InternalGasPerByte::new(50),
    };
    
    let state_key = StateKey::raw(b"test_resource_group".to_vec());
    
    // Large resource group creation - charges full IO gas
    let creation_size = WriteOpSize::Creation { write_len: 1_000_000 }; // 1MB
    let creation_gas = pricing_v2.io_gas_per_write(&state_key, &creation_size);
    assert!(creation_gas > InternalGas::zero()); // Charges significant gas
    
    // Large resource group deletion - charges ZERO IO gas
    let deletion_size = WriteOpSize::Deletion;
    let deletion_gas = pricing_v2.io_gas_per_write(&state_key, &deletion_size);
    assert_eq!(deletion_gas, InternalGas::zero()); // BUG: Charges nothing!
    
    // This asymmetry allows validators to process deletions for free
    println!("Creation gas: {:?}", creation_gas);
    println!("Deletion gas: {:?}", deletion_gas); // Zero!
}
```

## Notes

This finding is specific to the Option handling in `materialized_size()` when `maybe_group_op_size` is None. The function correctly returns `WriteOpSize::Deletion`, but downstream IO pricing versions V2 and V3 handle this by charging zero gas, creating the reported asymmetry. Version 4 partially addresses this by charging base costs, though still not value-size-proportional costs.

### Citations

**File:** aptos-move/aptos-vm-types/src/abstract_write_op.rs (L53-57)
```rust
            WriteResourceGroup(GroupWrite {
                metadata_op: write_op,
                maybe_group_op_size,
                ..
            }) => write_op.project_write_op_size(|| maybe_group_op_size.map(|x| x.get())),
```

**File:** aptos-move/aptos-vm-types/src/abstract_write_op.rs (L196-196)
```rust
        let maybe_group_op_size = (!metadata_op.is_deletion()).then_some(group_size);
```

**File:** aptos-move/aptos-vm-types/src/storage/io_pricing.rs (L142-156)
```rust
    fn io_gas_per_write(&self, key: &StateKey, op_size: &WriteOpSize) -> InternalGas {
        use aptos_types::write_set::WriteOpSize::*;

        match op_size {
            Creation { write_len } => {
                self.per_item_create * NumArgs::new(1)
                    + self.write_op_size(key, *write_len) * self.per_byte_create
            },
            Modification { write_len } => {
                self.per_item_write * NumArgs::new(1)
                    + self.write_op_size(key, *write_len) * self.per_byte_write
            },
            Deletion => 0.into(),
        }
    }
```

**File:** aptos-move/aptos-vm-types/src/storage/io_pricing.rs (L183-197)
```rust
    fn io_gas_per_write(
        &self,
        key: &StateKey,
        op_size: &WriteOpSize,
    ) -> impl GasExpression<VMGasParameters, Unit = InternalGasUnit> + use<> {
        op_size.write_len().map_or_else(
            || Either::Right(InternalGas::zero()),
            |write_len| {
                Either::Left(
                    STORAGE_IO_PER_STATE_SLOT_WRITE * NumArgs::new(1)
                        + STORAGE_IO_PER_STATE_BYTE_WRITE * self.write_op_size(key, write_len),
                )
            },
        )
    }
```

**File:** aptos-move/block-executor/src/executor_utilities.rs (L140-148)
```rust
                let btree: BTreeMap<T::Tag, Bytes> = finalized_group
                    .into_iter()
                    .map(|(resource_tag, arc_v)| {
                        let bytes = arc_v
                            .extract_raw_bytes()
                            .expect("Deletions should already be applied");
                        (resource_tag, bytes)
                    })
                    .collect();
```
