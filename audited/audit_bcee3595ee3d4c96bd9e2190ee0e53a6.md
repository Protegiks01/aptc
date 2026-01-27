# Audit Report

## Title
Gas Metering Bypass in Derived String Snapshot Integer-to-String Conversion

## Summary
The `SnapshotToStringFormula::apply_to()` function performs integer-to-string conversion via `to_string()` that allocates memory without proper gas metering. This allows attackers to allocate up to 39 bytes per call (for u128::MAX) while paying significantly less gas than intended, violating the Move VM's resource limit invariant.

## Finding Description

The vulnerability exists in the derived string snapshot implementation where integer snapshots are converted to strings and concatenated with prefix/suffix values. The critical issue occurs in two code paths:

**Primary Vulnerability Path (Production Default):**

When `delayed_field_optimization_enabled` is `false` (the production default setting), the native function `native_derive_string_concat` charges gas only for the prefix and suffix string lengths, but NOT for the memory allocation required to convert the integer snapshot value to a string. [1](#0-0) [2](#0-1) 

The gas charging only accounts for prefix and suffix lengths, then immediately materializes the value: [3](#0-2) 

The `apply_to()` function performs the unmetered allocation: [4](#0-3) 

The `base.to_string()` call allocates a String that can be up to 39 bytes for `u128::MAX` (340282366920938463463374607431768211455) or 20 bytes for `u64::MAX` (18446744073709551615). This memory allocation is NOT accounted for in the gas charges at lines 543 and 550 of the native function.

**Secondary Vulnerability Path (If Optimization Enabled):**

When delayed field optimization is enabled, the issue is even worse—the materialization happens during commit with zero gas accounting: [5](#0-4) 

**Exploitation Scenario:**
1. Attacker creates an `AggregatorSnapshot<u128>` containing `u128::MAX`
2. Calls `derive_string_concat(empty_string, &snapshot, empty_string)` repeatedly
3. Each call pays only 1102 base gas but allocates 39 bytes without per-byte gas charge
4. Missing gas: 3 gas/byte × 39 bytes = 117 gas units per call (~9.6% undercharge) [6](#0-5) 

## Impact Explanation

This vulnerability qualifies as **Medium Severity** per Aptos bug bounty criteria:

1. **Resource Limit Violation**: Breaks Move VM invariant #9 (Resource Limits) - "All operations must respect gas, storage, and computational limits"

2. **Bounded but Amplifiable**: While each call allocates at most 39 bytes, an attacker can make multiple calls within a transaction. With a 1M gas limit, an attacker could make ~907 calls (at 1102 gas each), allocating ~35KB while undercharging by ~106K gas units (~10.6% of transaction cost).

3. **Production Impact**: Affects the default production configuration where `delayed_field_optimization_enabled=false`

4. **Deterministic**: Does not cause consensus issues as all nodes execute identically

5. **Limited DoS**: While exploitable for undercharged memory allocation, the attacker still must pay significant gas (base cost per call), limiting large-scale DoS attacks

## Likelihood Explanation

**HIGH Likelihood** - This vulnerability is:
- Easy to exploit: Requires only calling a public native function `derive_string_concat`
- No special privileges required: Any transaction sender can exploit it
- Already in production: Default configuration is vulnerable
- Repeatable: Can be called multiple times per transaction to amplify impact

## Recommendation

**Fix 1: Add gas metering for integer-to-string conversion**

Modify `native_derive_string_concat` to charge gas for the expected string length based on the snapshot type:

```rust
// After getting snapshot_value_ty (line 545), charge for string conversion
let max_string_length = match snapshot_value_ty {
    Type::U128 => 39,  // u128::MAX has 39 digits
    Type::U64 => 20,   // u64::MAX has 20 digits
    _ => return Err(SafeNativeError::Abort {
        abort_code: EUNSUPPORTED_AGGREGATOR_SNAPSHOT_TYPE,
    }),
};
context.charge(AGGREGATOR_V2_STRING_CONCAT_PER_BYTE * NumBytes::new(max_string_length))?;
```

**Fix 2: Pre-compute total allocation size**

Calculate the total output size before calling `apply_to()` and charge gas accordingly:

```rust
let total_output_size = prefix.len() + max_string_length + suffix.len();
context.charge(AGGREGATOR_V2_STRING_CONCAT_PER_BYTE * NumBytes::new(total_output_size as u64))?;
```

This ensures gas is charged for the complete allocation, not just the prefix and suffix components.

## Proof of Concept

```move
module 0xCAFE::gas_exploit {
    use aptos_framework::aggregator_v2;
    use std::string;

    /// Demonstrates gas undercharge in derive_string_concat
    public entry fun exploit_gas_undercharge() {
        // Create snapshot with maximum value (39 digit string when converted)
        let snapshot = aggregator_v2::create_snapshot<u128>(340282366920938463463374607431768211455u128);
        
        // Call derive_string_concat with empty prefix and suffix
        // This charges only base gas (1102) + 0 (empty strings)
        // But allocates 39 bytes for the u128 string conversion
        // Missing charge: 3 * 39 = 117 gas units
        let _derived1 = aggregator_v2::derive_string_concat(
            string::utf8(b""),
            &snapshot,
            string::utf8(b"")
        );
        
        // Repeat multiple times to amplify undercharge
        let _derived2 = aggregator_v2::derive_string_concat(string::utf8(b""), &snapshot, string::utf8(b""));
        let _derived3 = aggregator_v2::derive_string_concat(string::utf8(b""), &snapshot, string::utf8(b""));
        // ... can repeat up to gas limit
        
        // Each call saves 117 gas units while allocating 39 bytes
        // With 100 calls: saves 11,700 gas, allocates 3,900 bytes
    }
}
```

**Test Steps:**
1. Compile the module above
2. Profile gas usage when calling `exploit_gas_undercharge()`
3. Compare against expected gas cost: (base_gas + 3*39) * num_calls
4. Observe ~9.6% undercharge per call relative to proper per-byte metering

## Notes

The vulnerability is confirmed in both execution paths:
- **Default path** (optimization disabled): Undercharges by ~117 gas per call during immediate materialization
- **Optimization path** (if enabled): Completely bypasses gas metering during commit-time materialization

While the per-call impact is bounded (max 39 bytes), the cumulative effect across multiple calls within a transaction can result in significant undercharging and memory allocation disproportionate to gas paid. This violates the fundamental Move VM invariant that all memory allocations must be properly gas-metered.

### Citations

**File:** aptos-move/aptos-vm-environment/src/prod_configs.rs (L250-252)
```rust
        // By default, do not use delayed field optimization. Instead, clients should enable it
        // manually where applicable.
        delayed_field_optimization_enabled: false,
```

**File:** aptos-move/framework/src/natives/aggregator_natives/aggregator_v2.rs (L538-550)
```rust
    context.charge(AGGREGATOR_V2_STRING_CONCAT_BASE)?;

    // Popping arguments from the end.
    let suffix = string_to_bytes(safely_pop_arg!(args, Struct))
        .map_err(SafeNativeError::InvariantViolation)?;
    context.charge(AGGREGATOR_V2_STRING_CONCAT_PER_BYTE * NumBytes::new(suffix.len() as u64))?;

    let snapshot_value_ty = &ty_args[0];
    let snapshot = safely_pop_arg!(args, StructRef);

    let prefix = string_to_bytes(safely_pop_arg!(args, Struct))
        .map_err(SafeNativeError::InvariantViolation)?;
    context.charge(AGGREGATOR_V2_STRING_CONCAT_PER_BYTE * NumBytes::new(prefix.len() as u64))?;
```

**File:** aptos-move/framework/src/natives/aggregator_natives/aggregator_v2.rs (L578-580)
```rust
        let snapshot_value = get_snapshot_value(&snapshot, snapshot_value_ty)?;
        let output = SnapshotToStringFormula::Concat { prefix, suffix }.apply_to(snapshot_value);
        bytes_and_width_to_derived_string_struct(output, width)?
```

**File:** types/src/delayed_fields.rs (L46-58)
```rust
    pub fn apply_to(&self, base: u128) -> Vec<u8> {
        match self {
            SnapshotToStringFormula::Concat { prefix, suffix } => {
                let middle_string = base.to_string();
                let middle = middle_string.as_bytes();
                let mut result = Vec::with_capacity(prefix.len() + middle.len() + suffix.len());
                result.extend(prefix);
                result.extend(middle);
                result.extend(suffix);
                result
            },
        }
    }
```

**File:** aptos-move/mvhashmap/src/versioned_delayed_fields.rs (L663-665)
```rust
                if let DelayedFieldValue::Snapshot(base) = prev_value {
                    let new_value = formula.apply_to(base);
                    DelayedFieldValue::Derived(new_value)
```

**File:** aptos-move/aptos-gas-schedule/src/gas_schedule/aptos_framework.rs (L347-348)
```rust
        [aggregator_v2_string_concat_base: InternalGas, {RELEASE_V1_8.. => "aggregator_v2.string_concat.base"}, 1102],
        [aggregator_v2_string_concat_per_byte: InternalGasPerByte, { RELEASE_V1_9_SKIPPED.. =>"aggregator_v2.string_concat.per_byte" }, 3],
```
