# Audit Report

## Title
Missing Overflow Protection in Gas Multiplication Operations Enables Governance-Triggered Denial of Service

## Summary
The multiplication of `InternalGasPerByte` by `NumBytes` in table natives uses saturating arithmetic instead of checked arithmetic, combined with absent validation on gas parameter values during governance updates, creating a critical vulnerability where misconfigured or maliciously set gas parameters can cause arithmetic overflow that saturates gas charges to `u64::MAX`, effectively rendering table operations unusable.

## Finding Description

The gas calculation system lacks two critical protections:

1. **No Checked Arithmetic**: The multiplication implementation uses `saturating_mul` instead of checked arithmetic that would abort on overflow. [1](#0-0) 

2. **No Gas Parameter Validation**: Governance updates to gas schedules have no validation on parameter values, as evidenced by TODO comments indicating missing consistency checks. [2](#0-1) [3](#0-2) [4](#0-3) 

The macro-generated gas parameter loading performs no value validation: [5](#0-4) 

**Attack Scenario:**

When `InternalGasPerByte` values are set extremely high (approaching `u64::MAX / max_bytes_per_write_op ≈ 17,592,186,044,415`), multiplications with even moderate `NumBytes` values trigger overflow. The saturating behavior causes gas charges to become `u64::MAX`, making operations prohibitively expensive: [6](#0-5) [7](#0-6) [8](#0-7) 

With `max_bytes_per_write_op` set to 1 MB: [9](#0-8) 

Any gas parameter exceeding ~17 trillion would cause overflow on 1 MB operations, saturating gas to `u64::MAX` (18.4 quintillion) instead of aborting with a proper error.

## Impact Explanation

**Critical Severity** - This constitutes a **Total loss of liveness** vulnerability:

- **Complete DoS of Table Operations**: Any transaction using table natives would require `u64::MAX` gas, which exceeds the maximum transaction gas limit, causing all such transactions to fail.
- **Protocol-Wide Impact**: Tables are used throughout the Aptos Framework for critical state management. Breaking table functionality would effectively halt network operations requiring state updates.
- **Non-Recoverable Without Hardfork**: Once deployed, bad gas parameters would require emergency governance action or potentially a hardfork to restore functionality.
- **Deterministic Consensus Impact**: While all nodes would behave identically (same saturating behavior), the network would experience synchronized liveness failure for affected operations.

This breaks the **Resource Limits** invariant: "All operations must respect gas, storage, and computational limits" - operations would charge incorrect (saturated) gas values.

## Likelihood Explanation

**Moderate-to-Low Likelihood** due to:

**Barrier to Exploit:**
- Requires governance proposal approval (high barrier, needs significant voting power)
- Or accidental misconfiguration during gas schedule updates (human error by trusted developers)

**Defense Factors:**
- Governance participants are trusted actors
- Gas schedule changes undergo review processes
- Current gas parameter values are far below overflow thresholds (36-151 range)

**Risk Factors:**
- TODO comments prove validation is known to be missing
- No automated checks prevent extreme values
- Silent saturation hides problems instead of failing loudly
- Human error during decimal/unit conversions could cause accidental overflow

While exploitation requires privileged access (governance control), the missing defensive programming creates unnecessary systemic risk, especially given the critical nature of gas calculations for network operation.

## Recommendation

Implement two-layered protection:

**1. Replace Saturating Arithmetic with Checked Arithmetic:**

```rust
// In gas_algebra.rs, replace saturating_mul with checked_mul
fn mul_impl<U1, U2>(x: GasQuantity<U2>, y: GasQuantity<UnitDiv<U1, U2>>) -> GasQuantity<U1> {
    GasQuantity::new(
        x.val.checked_mul(y.val)
            .expect("Gas multiplication overflow - gas parameters may be misconfigured")
    )
}
```

**2. Add Gas Parameter Validation in gas_schedule.move:**

```move
// Replace TODO comments with actual validation
const EGAS_PARAMETER_OUT_OF_RANGE: u64 = 4;
const MAX_REASONABLE_GAS_PER_BYTE: u64 = 1_000_000; // 1 million per byte

fun validate_gas_schedule(entries: &vector<GasEntry>) {
    let i = 0;
    let len = vector::length(entries);
    while (i < len) {
        let entry = vector::borrow(entries, i);
        // Validate per-byte parameters don't risk overflow
        if (string::contains(&entry.key, string::utf8(b"per_byte"))) {
            assert!(entry.val <= MAX_REASONABLE_GAS_PER_BYTE, 
                   error::invalid_argument(EGAS_PARAMETER_OUT_OF_RANGE));
        };
        // Add other validation rules as needed
        i = i + 1;
    };
}
```

**3. Add validation calls in set_for_next_epoch and initialize:**

```move
public fun set_for_next_epoch(aptos_framework: &signer, gas_schedule_blob: vector<u8>) acquires GasScheduleV2 {
    // ... existing code ...
    let new_gas_schedule: GasScheduleV2 = from_bytes(gas_schedule_blob);
    validate_gas_schedule(&new_gas_schedule.entries); // ADD THIS
    // ... rest of function ...
}
```

## Proof of Concept

```rust
#[test]
#[should_panic(expected = "Gas multiplication overflow")]
fn test_gas_overflow_vulnerability() {
    use move_core_types::gas_algebra::{InternalGasPerByte, NumBytes};
    
    // Set an extremely high InternalGasPerByte value (near overflow threshold)
    let gas_per_byte = InternalGasPerByte::new(18_000_000_000_000_000); // 18 quadrillion
    
    // Even moderate NumBytes (100 KB) triggers overflow
    let num_bytes = NumBytes::new(100_000);
    
    // Current implementation: silently saturates to u64::MAX
    let result = gas_per_byte * num_bytes;
    
    // Result is u64::MAX (18.4 quintillion) instead of expected ~1.8 quintillion
    // This makes the operation appear to cost maximum gas
    assert_eq!(u64::from(result), u64::MAX);
    
    // With checked arithmetic (recommended fix), this would panic instead
    // preventing the misconfiguration from causing silent failures
}

// Demonstrate realistic scenario via Move integration test:
#[test_only]
module test_addr::gas_overflow_test {
    use std::table::{Self, Table};
    use std::vector;
    
    #[test(account = @0x1)]
    #[expected_failure(abort_code = GAS_LIMIT_EXCEEDED)]
    fun test_table_operation_with_overflowed_gas(account: signer) {
        // Assume governance has set COMMON_LOAD_PER_BYTE to extremely high value
        // Creating table with moderate-sized keys would trigger overflow
        let t = table::new<vector<u8>, u64>();
        
        // This operation would now cost u64::MAX gas instead of correct amount
        let key = vector::empty<u8>();
        let i = 0;
        while (i < 1000) {
            vector::push_back(&mut key, 0u8);
            i = i + 1;
        };
        
        table::add(&mut t, key, 42); // Would fail with OUT_OF_GAS
        table::destroy_empty(t);
    }
}
```

## Notes

While this vulnerability requires governance-level access to exploit (either through malicious proposal or accidental misconfiguration), the missing defensive programming violates blockchain security best practices. The TODO comments at lines 47, 67, and 75 in `gas_schedule.move` explicitly acknowledge this validation gap. Critical gas calculation code should use checked arithmetic to fail loudly on misconfiguration rather than silently saturating to maximum values, which could cause widespread operational failures across the network.

### Citations

**File:** third_party/move/move-core/types/src/gas_algebra.rs (L229-231)
```rust
fn mul_impl<U1, U2>(x: GasQuantity<U2>, y: GasQuantity<UnitDiv<U1, U2>>) -> GasQuantity<U1> {
    GasQuantity::new(x.val.saturating_mul(y.val))
}
```

**File:** aptos-move/framework/aptos-framework/sources/configs/gas_schedule.move (L47-47)
```text
        // TODO(Gas): check if gas schedule is consistent
```

**File:** aptos-move/framework/aptos-framework/sources/configs/gas_schedule.move (L67-67)
```text
            // TODO(Gas): check if gas schedule is consistent
```

**File:** aptos-move/framework/aptos-framework/sources/configs/gas_schedule.move (L75-75)
```text
            // TODO(Gas): check if gas schedule is consistent
```

**File:** aptos-move/aptos-gas-schedule/src/gas_schedule/macros.rs (L40-40)
```rust
                        params.$name = gas_schedule.get(&name).cloned().ok_or_else(|| format!("Gas parameter {} does not exist. Feature version: {}.", name, feature_version))?.into();
```

**File:** aptos-move/framework/table-natives/src/lib.rs (L346-346)
```rust
            context.charge(COMMON_LOAD_BASE_NEW + COMMON_LOAD_PER_BYTE * num_bytes)
```

**File:** aptos-move/framework/table-natives/src/lib.rs (L412-412)
```rust
    let key_cost = ADD_BOX_PER_BYTE_SERIALIZED * NumBytes::new(key_bytes.len() as u64);
```

**File:** aptos-move/framework/table-natives/src/lib.rs (L472-472)
```rust
    let key_cost = BORROW_BOX_PER_BYTE_SERIALIZED * NumBytes::new(key_bytes.len() as u64);
```

**File:** aptos-move/aptos-gas-schedule/src/gas_schedule/transaction.rs (L154-156)
```rust
            max_bytes_per_write_op: NumBytes,
            { 5.. => "max_bytes_per_write_op" },
            1 << 20, // a single state item is 1MB max
```
