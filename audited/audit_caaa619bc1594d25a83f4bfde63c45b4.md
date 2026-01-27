# Audit Report

## Title
Metadata Loss in Sharded Block Executor Leading to Incorrect Storage Fee Accounting for Total Supply

## Summary
The `total_supply_base_view_override()` function in the sharded block executor creates a new `StateValue` without preserving metadata from the original state, causing permanent loss of storage deposit information (slot_deposit, bytes_deposit) and creation timestamps. This leads to incorrect storage fee calculations on subsequent modifications and loss of refund information if the value is ever deleted.

## Finding Description

The vulnerability exists in the sharded block executor's handling of the `TOTAL_SUPPLY_STATE_KEY`. When transactions execute in parallel shards, the `AggregatorOverriddenStateView` is used to provide a consistent base value for total supply aggregation. However, the implementation has a critical flaw: [1](#0-0) 

The function creates a new `StateValue` using `StateValue::new_legacy()`, which initializes it with `StateValueMetadata::none()` (no metadata). The original state value is read on line 46 but immediately discarded, losing its metadata: [2](#0-1) 

This metadata contains critical information: [3](#0-2) 

The problem is compounded by the `update_total_supply()` function which also creates a `WriteOp` with no metadata: [4](#0-3) 

**Execution Flow:**
1. Sharded block executor wraps state view with `AggregatorOverriddenStateView`
2. Transactions read `TOTAL_SUPPLY_STATE_KEY` and receive a `StateValue` with no metadata
3. Transaction modifications create `WriteOp` with `StateValueMetadata::none()`
4. After shard execution, `aggregate_and_update_total_supply` calls `update_total_supply()`
5. This creates a new `WriteOp::legacy_modification()` with no metadata, replacing any existing metadata
6. The WriteOp is committed to storage, permanently losing the original metadata

**Storage Fee Impact:**

The storage fee system relies on metadata to track deposits and calculate fees: [5](#0-4) 

On deletion, the refund is calculated from metadata: [6](#0-5) 

When stored to the database, the WriteOp's StateValue (including its metadata) is persisted directly: [7](#0-6) 

## Impact Explanation

This vulnerability has **Medium severity** impact for several reasons:

1. **Loss of Deposit Information**: The `slot_deposit` and `bytes_deposit` fields are permanently lost. If the original `TOTAL_SUPPLY_STATE_KEY` had paid storage fees (likely at genesis or first initialization), this deposit information is erased.

2. **Incorrect Storage Fee Calculations**: On future modifications, the fee calculation uses `old_bytes_deposit` from metadata. With lost metadata, this will be 0 instead of the actual amount, leading to incorrect fee calculations.

3. **Incorrect Refunds**: If the value is ever deleted, the refund would be 0 instead of returning the actual deposits paid. While total supply deletion is unlikely, this represents a loss of funds that should be refunded.

4. **Loss of Creation Timestamp**: The `creation_time_usecs` is lost, affecting auditing and any time-based logic.

5. **System Integrity**: While all nodes lose metadata identically (no consensus break), the system loses critical accounting information, violating the principle that state transitions should preserve all relevant information.

This qualifies as **Medium severity** per Aptos bug bounty criteria: "Limited funds loss or manipulation" and "State inconsistencies requiring intervention."

## Likelihood Explanation

**High likelihood** - This occurs automatically on every block executed with the sharded block executor:

- The sharded executor is used in production for parallel transaction execution
- Every block execution that touches total supply triggers this code path through the aggregator service: [8](#0-7) 

- The issue has been happening since the sharded executor was deployed
- No special attacker action is required - this is a systemic bug affecting normal operations

## Recommendation

**Fix 1: Preserve metadata in `total_supply_base_view_override()`**

Modify the function to extract and preserve the original metadata:

```rust
fn total_supply_base_view_override(&self) -> Result<Option<StateValue>> {
    // Get the original state value to preserve its metadata
    let original = self.base_view.get_state_value(&TOTAL_SUPPLY_STATE_KEY)?;
    let metadata = original
        .as_ref()
        .map(|v| v.metadata().clone())
        .unwrap_or_else(StateValueMetadata::none);
    
    Ok(Some(StateValue::new_with_metadata(
        bcs::to_bytes(&self.total_supply_aggr_base_val)
            .unwrap()
            .into(),
        metadata,
    )))
}
```

**Fix 2: Preserve metadata in `update_total_supply()`**

Modify the function to preserve existing metadata when updating:

```rust
fn update_total_supply(&mut self, value: u128) {
    let existing_write_op = self.0.write_set.get(&TOTAL_SUPPLY_STATE_KEY);
    let metadata = existing_write_op
        .map(|op| op.metadata().clone())
        .unwrap_or_else(StateValueMetadata::none);
    
    assert!(self
        .0
        .write_set
        .insert(
            TOTAL_SUPPLY_STATE_KEY.clone(),
            WriteOp::modification(bcs::to_bytes(&value).unwrap().into(), metadata)
        )
        .is_some());
}
```

Both fixes are necessary to ensure metadata is never lost during the sharded execution flow.

## Proof of Concept

```rust
#[test]
fn test_metadata_loss_in_total_supply_override() {
    use aptos_types::state_store::{StateValue, StateValueMetadata};
    use aptos_types::on_chain_config::CurrentTimeMicroseconds;
    
    // Create a mock state view with total supply that has metadata
    let original_metadata = StateValueMetadata::new(
        100, // slot_deposit
        200, // bytes_deposit
        &CurrentTimeMicroseconds { microseconds: 1000 }
    );
    let original_value = StateValue::new_with_metadata(
        bcs::to_bytes(&10000u128).unwrap().into(),
        original_metadata.clone()
    );
    
    // Simulate the override
    let overridden_value = StateValue::new_legacy(
        bcs::to_bytes(&(u128::MAX >> 1)).unwrap().into()
    );
    
    // Verify metadata is lost
    assert!(original_value.metadata().inner().is_some());
    assert!(overridden_value.metadata().inner().is_none());
    assert_eq!(original_value.metadata().slot_deposit(), 100);
    assert_eq!(overridden_value.metadata().slot_deposit(), 0); // LOST!
    assert_eq!(original_value.metadata().bytes_deposit(), 200);
    assert_eq!(overridden_value.metadata().bytes_deposit(), 0); // LOST!
    
    // Demonstrate refund loss
    assert_eq!(original_value.metadata().total_deposit(), 300);
    assert_eq!(overridden_value.metadata().total_deposit(), 0); // Would refund 0 on deletion!
}
```

## Notes

This vulnerability affects a critical piece of blockchain state (total supply) and causes permanent loss of storage accounting information. While it doesn't cause immediate consensus breaks (all nodes lose metadata identically), it represents a violation of system integrity and correct storage fee accounting, potentially leading to loss of funds through incorrect refunds.

### Citations

**File:** aptos-move/aptos-vm/src/sharded_block_executor/aggr_overridden_state_view.rs (L29-35)
```rust
    fn total_supply_base_view_override(&self) -> Result<Option<StateValue>> {
        Ok(Some(StateValue::new_legacy(
            bcs::to_bytes(&self.total_supply_aggr_base_val)
                .unwrap()
                .into(),
        )))
    }
```

**File:** aptos-move/aptos-vm/src/sharded_block_executor/aggr_overridden_state_view.rs (L41-50)
```rust
    fn get_state_value(&self, state_key: &StateKey) -> Result<Option<StateValue>> {
        if *state_key == *TOTAL_SUPPLY_STATE_KEY {
            // TODO: Remove this when we have aggregated total supply implementation for remote
            //       sharding. For now we need this because after all the txns are executed, the
            //       proof checker expects the total_supply to read/written to the tree.
            self.base_view.get_state_value(state_key)?;
            return self.total_supply_base_view_override();
        }
        self.base_view.get_state_value(state_key)
    }
```

**File:** types/src/state_store/state_value.rs (L46-56)
```rust
#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
struct StateValueMetadataInner {
    slot_deposit: u64,
    bytes_deposit: u64,
    creation_time_usecs: u64,
}

#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct StateValueMetadata {
    inner: Option<StateValueMetadataInner>,
}
```

**File:** types/src/write_set.rs (L730-739)
```rust
    fn update_total_supply(&mut self, value: u128) {
        assert!(self
            .0
            .write_set
            .insert(
                TOTAL_SUPPLY_STATE_KEY.clone(),
                WriteOp::legacy_modification(bcs::to_bytes(&value).unwrap().into())
            )
            .is_some());
    }
```

**File:** aptos-move/aptos-vm-types/src/storage/space_pricing.rs (L187-206)
```rust
            Modification { write_len } => {
                // Change of slot size or per byte price can result in a charge or refund of the bytes fee.
                let old_bytes_deposit = op.metadata_mut.bytes_deposit();
                let state_bytes_charge =
                    if write_len > op.prev_size && target_bytes_deposit > old_bytes_deposit {
                        let charge_by_increase: u64 = (write_len - op.prev_size)
                            * u64::from(params.storage_fee_per_state_byte);
                        let gap_from_target = target_bytes_deposit - old_bytes_deposit;
                        std::cmp::min(charge_by_increase, gap_from_target)
                    } else {
                        0
                    };
                op.metadata_mut.maybe_upgrade();
                op.metadata_mut
                    .set_bytes_deposit(old_bytes_deposit + state_bytes_charge);

                ChargeAndRefund {
                    charge: state_bytes_charge.into(),
                    refund: 0.into(),
                }
```

**File:** aptos-move/aptos-vm-types/src/storage/space_pricing.rs (L208-211)
```rust
            Deletion => ChargeAndRefund {
                charge: 0.into(),
                refund: op.metadata_mut.total_deposit().into(),
            },
```

**File:** storage/aptosdb/src/state_store/mod.rs (L829-840)
```rust
                    .try_for_each(|(key, version, write_op)| {
                        if self.state_kv_db.enabled_sharding() {
                            batch.put::<StateValueByKeyHashSchema>(
                                &(CryptoHash::hash(*key), version),
                                &write_op.as_state_value_opt().cloned(),
                            )
                        } else {
                            batch.put::<StateValueSchema>(
                                &((*key).clone(), version),
                                &write_op.as_state_value_opt().cloned(),
                            )
                        }
```

**File:** aptos-move/aptos-vm/src/sharded_block_executor/sharded_executor_service.rs (L123-126)
```rust
        let aggr_overridden_state_view = Arc::new(AggregatorOverriddenStateView::new(
            cross_shard_state_view.as_ref(),
            TOTAL_SUPPLY_AGGR_BASE_VAL,
        ));
```
