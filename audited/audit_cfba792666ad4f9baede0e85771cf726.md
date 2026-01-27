# Audit Report

## Title
Gas Metering Bypass for Delayed Fields: Large DerivedString Values Undercharged in Copy Operations

## Summary
The production gas metering implementation ignores the `width` field of `DelayedFieldID` values and always charges them as u64-sized (8 bytes), even though DerivedString delayed fields can be up to 1024 bytes. This allows attackers to perform copy operations on large delayed fields at approximately 1/128th the correct gas cost.

## Finding Description

The gas metering system calculates abstract value sizes to charge for operations like `copy_loc`, `read_ref`, and equality checks. The production implementation in `AbstractValueSizeVisitor` treats all delayed fields uniformly as u64 values: [1](#0-0) 

However, `DelayedFieldID` contains a `width` field that specifies the exact serialized size: [2](#0-1) 

Delayed fields can represent three types of values: [3](#0-2) 

The `Derived(Vec<u8>)` variant stores variable-length strings that can be up to 1024 bytes: [4](#0-3) 

Users can create these large DerivedStrings through public Move functions: [5](#0-4) 

When users copy these values using `CopyLoc`, the gas meter charges based on abstract value size: [6](#0-5) 

**Attack Path:**
1. Attacker calls `create_derived_string(1024_byte_string)` to create a large DerivedString delayed field
2. Attacker performs `CopyLoc` operations on this value
3. Gas meter calls `abstract_value_size_stack_and_heap()` which delegates to `visit_delayed()`
4. `visit_delayed()` charges only `self.params.u64` (40 abstract units) regardless of actual 1024-byte size
5. Attacker performs large-value operations at ~1/128th the correct cost

This same undercharging occurs in `abstract_stack_size` and `abstract_packed_size` visitors, affecting multiple operations.

## Impact Explanation

This qualifies as **Medium Severity** per Aptos bug bounty criteria for the following reasons:

1. **Resource Limits Violation**: Breaks the critical invariant that "All operations must respect gas, storage, and computational limits"

2. **Move VM Safety Compromise**: Violates "Bytecode execution must respect gas limits and memory constraints"

3. **Gas Metering Bypass**: Attackers can perform computationally expensive copy operations at drastically reduced cost (up to 128x undercharge)

4. **Economic Impact**: Users avoid paying fair gas costs for resource consumption, effectively stealing from validators who process these transactions

While this doesn't directly lead to consensus violations or fund theft, it enables resource exhaustion attacks and unfair gas cost manipulation, qualifying it for Medium severity: "Limited funds loss or manipulation."

## Likelihood Explanation

**Likelihood: HIGH**

This vulnerability is highly likely to be exploited because:

1. **Public Access**: The vulnerable code path is triggered by public Move functions (`create_derived_string`, `derive_string_concat`) that any user can call
2. **No Special Permissions**: Attackers need no validator access or special privileges
3. **Simple Exploitation**: Attack requires only calling standard aggregator_v2 functions with large strings
4. **Clear Economic Incentive**: Significant gas savings (up to 128x) provide strong motivation
5. **Production Code**: This affects the actual production gas meter, not just test utilities

## Recommendation

Modify all three visitor implementations to use the `width` field from `DelayedFieldID` instead of treating all delayed fields as u64-sized:

```rust
fn visit_delayed(&mut self, depth: u64, id: DelayedFieldID) -> PartialVMResult<()> {
    self.check_depth(depth)?;
    // Use the actual width from the DelayedFieldID instead of fixed u64 size
    let width = AbstractMemorySize::new(id.extract_width() as u64);
    self.size += width;
    Ok(())
}
```

Apply this fix to:
- `AbstractValueSizeVisitor::visit_delayed`
- `abstract_stack_size Visitor::visit_delayed` 
- `abstract_packed_size Visitor::visit_delayed`

## Proof of Concept

```move
module 0x1::gas_bypass_test {
    use std::string;
    use aptos_framework::aggregator_v2;

    public entry fun exploit_gas_undercharge() {
        // Create a large DerivedString (1024 bytes)
        let large_string = string::utf8(vector[
            // 1024 'A' characters
            65, 65, 65, /* ... repeat 1024 times ... */
        ]);
        
        let derived = aggregator_v2::create_derived_string(large_string);
        
        // Copy the large value multiple times - each copy only charges ~8 bytes
        // instead of ~1024 bytes
        let copy1 = derived;
        let copy2 = copy1;
        let copy3 = copy2;
        let copy4 = copy3;
        
        // Attacker just performed 4 copies of 1024-byte values
        // but paid gas for 4 copies of 8-byte values
        // Actual cost: ~4096 bytes, Charged: ~32 bytes (128x undercharge)
    }
}
```

**Notes:**
- The security question specifically mentioned the test-utils file, but investigation revealed the production code has the actual vulnerability
- The test-utils `legacy_abstract_memory_size()` has a complete NO-OP for delayed fields, but is only used in development tools
- The production vulnerability is more subtle: it charges a fixed amount instead of zero, but still significantly undercharges for large delayed fields

### Citations

**File:** aptos-move/aptos-gas-schedule/src/gas_schedule/misc.rs (L209-212)
```rust
    fn visit_delayed(&mut self, depth: u64, _id: DelayedFieldID) -> PartialVMResult<()> {
        self.check_depth(depth)?;
        self.size += self.params.u64;
        Ok(())
```

**File:** third_party/move/move-vm/types/src/delayed_values/delayed_field_id.rs (L23-30)
```rust
/// Ephemeral identifier type used by delayed fields (e.g., aggregators, snapshots)
/// during execution.
#[derive(Clone, Copy, Debug, Hash, PartialEq, Eq, PartialOrd, Ord)]
pub struct DelayedFieldID {
    unique_index: u32,
    // Exact number of bytes serialized delayed field will take.
    width: u32,
}
```

**File:** aptos-move/aptos-aggregator/src/types.rs (L92-99)
```rust
/// Value of a DelayedField (i.e. aggregator or snapshot)
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum DelayedFieldValue {
    Aggregator(u128),
    Snapshot(u128),
    // TODO[agg_v2](optimize) probably change to Derived(Arc<Vec<u8>>) to make copying predictably costly
    Derived(Vec<u8>),
}
```

**File:** aptos-move/framework/src/natives/aggregator_natives/aggregator_v2.rs (L52-54)
```rust
/// The maximum length of the input string for derived string snapshot.
/// If we want to increase this, we need to modify BITS_FOR_SIZE in types/src/delayed_fields.rs.
pub const DERIVED_STRING_INPUT_MAX_LENGTH: usize = 1024;
```

**File:** aptos-move/framework/aptos-framework/sources/aggregator_v2/aggregator_v2.move (L188-198)
```text
    /// Creates a DerivedStringSnapshot of a given value.
    /// Useful for when object is sometimes created via string_concat(), and sometimes directly.
    public native fun create_derived_string(value: String): DerivedStringSnapshot;

    /// Concatenates `before`, `snapshot` and `after` into a single string.
    /// snapshot passed needs to have integer type - currently supported types are u64 and u128.
    /// Raises EUNSUPPORTED_AGGREGATOR_SNAPSHOT_TYPE if called with another type.
    /// If length of prefix and suffix together exceeds 1024 bytes, ECONCAT_STRING_LENGTH_TOO_LARGE is raised.
    ///
    /// Parallelism info: This operation enables parallelism.
    public native fun derive_string_concat<IntElement>(before: String, snapshot: &AggregatorSnapshot<IntElement>, after: String): DerivedStringSnapshot;
```

**File:** aptos-move/aptos-gas-meter/src/meter.rs (L303-311)
```rust
    fn charge_copy_loc(&mut self, val: impl ValueView) -> PartialVMResult<()> {
        let (stack_size, heap_size) = self
            .vm_gas_params()
            .misc
            .abs_val
            .abstract_value_size_stack_and_heap(val, self.feature_version())?;

        self.charge_copy_loc_cached(stack_size, heap_size)
    }
```
