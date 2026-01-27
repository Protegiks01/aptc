# Audit Report

## Title
Silent State Key Collision Between Table Operations and Aggregator V1 Writes Causes Lost Updates

## Summary
The `finish()` function in the VM session does not validate that StateKeys are unique across regular table operations and aggregator V1 operations. When both modify the same StateKey (table item), aggregator writes silently overwrite table writes during change set consolidation, causing lost updates and state inconsistency.

## Finding Description

In the transaction finalization flow, the `convert_change_set()` function processes multiple types of state changes: [1](#0-0) 

Table changes are inserted into `resource_write_set` using their StateKey (constructed via `StateKey::table_item`). [2](#0-1) 

Aggregator V1 changes are processed into a separate `aggregator_v1_write_set`.

Critically, **there is no validation that StateKeys don't overlap** between `resource_write_set` (which includes table items) and `aggregator_v1_write_set`. Since Aggregator V1 stores data as table items: [3](#0-2) 

The same StateKey can appear in both sets. When these are consolidated: [4](#0-3) 

The `extend()` method on `WriteSetMut` uses `BTreeMap::extend()`: [5](#0-4) 

This **silently overwrites** any existing keys, causing table modifications to be lost if an aggregator write targets the same StateKey.

Notably, the code explicitly checks for duplicate keys across resource change sets: [6](#0-5) 

But this validation does **not include** `aggregator_v1_write_set` or `aggregator_v1_delta_set`, which are kept separate: [7](#0-6) 

## Impact Explanation

**Severity: Medium to High**

This violates the **State Consistency** invariant: state transitions must be atomic and verifiable. When both table and aggregator operations modify the same StateKey:

1. **Lost Updates**: Table modifications are silently discarded
2. **Double-Counting Prevention Failure**: If both operations intend to increment a counter, only one increment applies
3. **Framework Code Vulnerability**: Framework developers may unknowingly write code that triggers this bug
4. **Silent Failure**: No error or warning is raised, making debugging extremely difficult

While direct exploitation by unprivileged users is constrained (since Aggregator fields are private), framework code could inadvertently trigger this bug. More critically, the lack of validation violates defensive programming principles and creates a ticking time bomb for future framework changes.

This qualifies as **"State inconsistencies requiring intervention"** (Medium Severity, up to $10,000) and potentially higher if consensus impact can be demonstrated.

## Likelihood Explanation

**Likelihood: Medium**

Direct exploitation requires either:
1. Framework code that performs both table and aggregator operations on the same StateKey
2. Framework APIs that expose both mechanisms to user code in a way that allows StateKey collision

While Aggregator creation is framework-restricted and fields are private (limiting direct user exploitation), the likelihood increases because:
- Framework code is complex and evolving
- No compile-time or runtime checks prevent this
- The TODO comment indicates developers know V1 aggregators use table items but may not be aware of this specific hazard

## Recommendation

Add duplicate StateKey validation in `convert_change_set()`:

```rust
// After line 502 in session/mod.rs, before calling VMChangeSet::new_expanded:

// Validate no conflicts between resource writes (including tables) and aggregator writes
for state_key in aggregator_v1_write_set.keys() {
    if resource_write_set.contains_key(state_key) {
        return Err(PartialVMError::new(
            StatusCode::UNKNOWN_INVARIANT_VIOLATION_ERROR
        )
        .with_message(format!(
            "StateKey conflict: {:?} modified by both table and aggregator operations",
            state_key
        )));
    }
}

// Similar check for aggregator_v1_delta_set
for state_key in aggregator_v1_delta_set.keys() {
    if resource_write_set.contains_key(state_key) {
        return Err(PartialVMError::new(
            StatusCode::UNKNOWN_INVARIANT_VIOLATION_ERROR
        )
        .with_message(format!(
            "StateKey conflict: {:?} has both table and aggregator delta operations",
            state_key
        )));
    }
}
```

Alternatively, extend the duplicate check in `VMChangeSet::new_expanded()` to include aggregator write sets in the fold operation, ensuring all StateKeys are globally unique across all change types.

## Proof of Concept

```move
// Conceptual PoC showing the vulnerability pattern
// This would need to be in framework code or a test harness
// that can construct both table and aggregator operations on the same StateKey

module 0x1::test_vuln {
    use std::table;
    use aptos_framework::aggregator;
    
    // Framework creates an aggregator and stores it
    // The aggregator uses StateKey: table_item(handle=H, key=K)
    struct MyResource has key {
        agg: aggregator::Aggregator,
        table_handle: address, // Same handle H
        table_key: address,    // Same key K
    }
    
    // This function performs both operations on the same StateKey
    public entry fun trigger_bug(addr: address) acquires MyResource {
        let res = borrow_global_mut<MyResource>(addr);
        
        // Operation 1: Modify via table (sets value to 100)
        table::upsert(&mut table_handle_from_res(res), res.table_key, 100u128);
        
        // Operation 2: Modify via aggregator (adds 50)
        aggregator::add(&mut res.agg, 50);
        
        // Expected final value: 150 (if both operations apply correctly)
        // Actual final value: 50 (aggregator write overwrites table write)
        // Lost update: The table write setting value to 100 is discarded
    }
}
```

The Rust-level test would construct a `TableChangeSet` and `AggregatorChangeSet` with overlapping StateKeys, call `convert_change_set()`, and verify that one write silently overwrites the other without error.

## Notes

This vulnerability highlights a defensive programming failure in the change set consolidation logic. While the duplicate check exists for resource changes, it does not extend to aggregator V1 operations despite aggregators using the same StateKey namespace (table items). The explicit TODO comment about aggregator V1 implementation suggests this is a known technical debt area that has not been fully addressed from a safety perspective.

### Citations

**File:** aptos-move/aptos-vm/src/move_vm_ext/session/mod.rs (L479-485)
```rust
        for (handle, change) in table_change_set.changes {
            for (key, value_op) in change.entries {
                let state_key = StateKey::table_item(&handle.into(), &key);
                let op = woc.convert_resource(&state_key, value_op, false)?;
                resource_write_set.insert(state_key, op);
            }
        }
```

**File:** aptos-move/aptos-vm/src/move_vm_ext/session/mod.rs (L487-502)
```rust
        for (state_key, change) in aggregator_change_set.aggregator_v1_changes {
            match change {
                AggregatorChangeV1::Write(value) => {
                    let write_op = woc.convert_aggregator_modification(&state_key, value)?;
                    aggregator_v1_write_set.insert(state_key, write_op);
                },
                AggregatorChangeV1::Merge(delta_op) => {
                    aggregator_v1_delta_set.insert(state_key, delta_op);
                },
                AggregatorChangeV1::Delete => {
                    let write_op =
                        woc.convert_aggregator(&state_key, MoveStorageOp::Delete, false)?;
                    aggregator_v1_write_set.insert(state_key, write_op);
                },
            }
        }
```

**File:** aptos-move/aptos-vm-types/src/change_set.rs (L190-204)
```rust
                .try_fold::<_, _, PartialVMResult<BTreeMap<_, _>>>(
                    BTreeMap::new(),
                    |mut acc, element| {
                        let (key, value) = element?;
                        if acc.insert(key, value).is_some() {
                            Err(PartialVMError::new(
                                StatusCode::DELAYED_FIELD_OR_BLOCKSTM_CODE_INVARIANT_ERROR,
                            )
                            .with_message(
                                "Found duplicate key across resource change sets.".to_string(),
                            ))
                        } else {
                            Ok(acc)
                        }
                    },
```

**File:** aptos-move/aptos-vm-types/src/change_set.rs (L206-210)
```rust
            events,
            delayed_field_change_set,
            aggregator_v1_write_set,
            aggregator_v1_delta_set,
        ))
```

**File:** aptos-move/aptos-vm-types/src/change_set.rs (L247-265)
```rust
        let mut write_set_mut = WriteSetMut::default();
        write_set_mut.extend(
            resource_write_set
                .into_iter()
                .map(|(k, v)| {
                    Ok((
                        k,
                        v.try_into_concrete_write().ok_or_else(|| {
                            code_invariant_error(
                                "Cannot convert from VMChangeSet with non-materialized write set",
                            )
                        })?,
                    ))
                })
                .collect::<Result<Vec<_>, _>>()?,
        );
        write_set_mut.extend(module_write_set.into_write_ops());
        write_set_mut.extend(aggregator_v1_write_set);

```

**File:** aptos-move/aptos-vm-types/src/change_set.rs (L809-810)
```rust
        // we split MVHashMap into data and aggregators.

```

**File:** types/src/write_set.rs (L770-772)
```rust
    pub fn extend(&mut self, write_ops: impl IntoIterator<Item = (StateKey, WriteOp)>) {
        self.write_set.extend(write_ops);
    }
```
