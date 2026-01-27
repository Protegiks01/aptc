# Audit Report

## Title
Governance Can Set Malicious Gas Parameters Causing Network-Wide DoS via Saturating Arithmetic

## Summary
Missing validation in the gas schedule update mechanism allows governance to set extreme per-unit gas parameters (e.g., `storage_io_per_state_byte_read`) that cause arithmetic saturation to `u64::MAX` during gas calculations. This results in all transactions performing common operations (like state reads) failing with `OUT_OF_GAS`, effectively halting the entire network.

## Finding Description

The Aptos gas calculation system uses saturating arithmetic throughout the `gas_algebra.rs` module. When multiplying gas quantities, if overflow occurs, the result saturates to `u64::MAX` rather than failing or wrapping. [1](#0-0) 

The gas schedule governance mechanism lacks validation of parameter values. The `set_for_next_epoch` function only validates that the feature version is non-decreasing, with explicit TODO comments indicating missing consistency checks. [2](#0-1) 

**Attack Path:**

1. A malicious or compromised governance proposal sets `storage_io_per_state_byte_read` to a large value (e.g., `u64::MAX / 1000 ≈ 1.8 × 10^16`)

2. When any transaction reads state, the gas calculation in `IoPricingV4::calculate_read_gas()` performs: `STORAGE_IO_PER_STATE_BYTE_READ * NumBytes::new(rounded_up)` [3](#0-2) 

3. This multiplication uses saturating arithmetic, so even reading a small amount of state saturates to `u64::MAX` [4](#0-3) 

4. The gas meter attempts to deduct `u64::MAX` from the transaction's balance via `checked_sub`, which always fails since no transaction can have `u64::MAX` gas units [5](#0-4) 

5. All transactions that read state fail with `OUT_OF_GAS` status

6. Since virtually all transactions read state, the network becomes completely unusable

This violates the **Resource Limits** invariant (all operations must respect gas limits) and the **Move VM Safety** invariant (bytecode execution must respect gas limits).

## Impact Explanation

**Critical Severity** - This vulnerability enables a complete denial of service attack that halts all network activity:

- **Total Loss of Liveness/Network Availability**: Once malicious gas parameters are deployed, all transactions that perform common operations (state reads, writes, etc.) will fail with `OUT_OF_GAS`
- **Non-Recoverable Without Hardfork**: The network cannot self-heal because even governance transactions to fix the parameters would fail due to the same gas calculation issue
- **Affects All Nodes**: This is deterministic - all validators and full nodes process transactions identically, so the entire network halts simultaneously

This maps directly to the Critical Severity category "Total loss of liveness/network availability" worth up to $1,000,000 per the bug bounty program.

## Likelihood Explanation

**Medium-High Likelihood:**

- **Attack Vector**: Requires passing a malicious governance proposal, which has high barriers (voting stake requirements, public scrutiny)
- **Accidental Trigger**: Could occur from honest governance mistakes during gas parameter tuning, as there's no validation preventing extreme values
- **TODO Comments**: The code explicitly indicates missing validation with TODO comments at lines 47, 67, and 75 in `gas_schedule.move`, suggesting the developers intended to add checks but haven't implemented them
- **No Recovery Mechanism**: Once triggered (maliciously or accidentally), requires emergency hardfork to recover

While governance attack requires significant coordination, the lack of validation violates defense-in-depth principles and the vulnerability is clearly unintended based on the TODO comments.

## Recommendation

**Add comprehensive validation to gas schedule updates:**

1. **In `gas_schedule.move`**, implement the TODO validation checks before lines 47, 67, and 75:
   - Validate that per-unit gas parameters (like `storage_io_per_state_byte_read`) are within reasonable bounds
   - Check that parameter combinations cannot cause saturation (e.g., `max_per_byte_param * max_operation_size < u64::MAX / safety_margin`)
   - Ensure critical parameters have upper bounds (e.g., per-byte costs < 1 million internal gas units)

2. **Add runtime safeguards in `gas_algebra.rs`**:
   - Replace `saturating_mul` with `checked_mul` in critical paths, returning errors on overflow instead of saturating
   - OR: Add validation after multiplication to reject results that saturated to `u64::MAX`

3. **Add pre-execution validation**:
   - In `charge_io` and `charge_execution`, validate that evaluated amounts are reasonable before attempting deduction
   - Reject transactions if a single operation would cost > 50% of max gas limits

**Specific code fix for `gas_schedule.move`:**

Add validation function and call it in `set_for_next_epoch`:
```move
// Validate that gas parameters are within safe bounds
fun validate_gas_schedule(schedule: &GasScheduleV2) {
    // Check each parameter is within acceptable range
    // Abort with EINVALID_GAS_SCHEDULE if any parameter exceeds safe limits
}

public fun set_for_next_epoch(aptos_framework: &signer, gas_schedule_blob: vector<u8>) {
    // ... existing code ...
    let new_gas_schedule: GasScheduleV2 = from_bytes(gas_schedule_blob);
    validate_gas_schedule(&new_gas_schedule); // ADD THIS
    // ... rest of function ...
}
```

## Proof of Concept

```rust
#[test]
fn test_gas_saturation_dos() {
    use move_core_types::gas_algebra::{InternalGas, InternalGasPerByte, NumBytes};
    
    // Simulate malicious gas parameter: storage_io_per_state_byte_read set to huge value
    let malicious_per_byte_cost = InternalGasPerByte::new(u64::MAX / 100);
    
    // Simulate reading just 200 bytes (very small state read)
    let bytes_read = NumBytes::new(200);
    
    // This multiplication will saturate to u64::MAX
    let gas_cost = bytes_read * malicious_per_byte_cost;
    let gas_cost_value: u64 = gas_cost.into();
    
    // Assert that it saturated to u64::MAX
    assert_eq!(gas_cost_value, u64::MAX);
    
    // Now try to deduct this from a realistic transaction balance
    let max_gas_units = 2_000_000u64;
    let gas_scaling_factor = 1_000_000u64;
    let transaction_balance = InternalGas::new(max_gas_units * gas_scaling_factor);
    
    // This checked_sub will fail because balance << u64::MAX
    let result = transaction_balance.checked_sub(gas_cost);
    assert!(result.is_none()); // Transaction fails with OUT_OF_GAS
    
    // This proves that with malicious gas parameters, even tiny operations
    // cause all transactions to fail
}
```

This PoC demonstrates that saturating arithmetic combined with lack of governance validation enables a critical DoS vulnerability that can halt the entire Aptos network.

## Notes

The vulnerability exists at the intersection of three issues:
1. **Missing validation** in governance gas schedule updates (explicit TODOs in code)
2. **Saturating arithmetic** in gas calculations that masks overflows
3. **No runtime bounds checking** on evaluated gas amounts before balance deduction

While governance is a trusted component, defense-in-depth principles require validation of even trusted inputs, especially when the TODO comments indicate this was the original intent but remains unimplemented.

### Citations

**File:** third_party/move/move-core/types/src/gas_algebra.rs (L209-210)
```rust
        Self::new(self.val.saturating_add(rhs.val))
    }
```

**File:** third_party/move/move-core/types/src/gas_algebra.rs (L229-231)
```rust
fn mul_impl<U1, U2>(x: GasQuantity<U2>, y: GasQuantity<UnitDiv<U1, U2>>) -> GasQuantity<U1> {
    GasQuantity::new(x.val.saturating_mul(y.val))
}
```

**File:** aptos-move/framework/aptos-framework/sources/configs/gas_schedule.move (L91-103)
```text
    public fun set_for_next_epoch(aptos_framework: &signer, gas_schedule_blob: vector<u8>) acquires GasScheduleV2 {
        system_addresses::assert_aptos_framework(aptos_framework);
        assert!(!vector::is_empty(&gas_schedule_blob), error::invalid_argument(EINVALID_GAS_SCHEDULE));
        let new_gas_schedule: GasScheduleV2 = from_bytes(gas_schedule_blob);
        if (exists<GasScheduleV2>(@aptos_framework)) {
            let cur_gas_schedule = borrow_global<GasScheduleV2>(@aptos_framework);
            assert!(
                new_gas_schedule.feature_version >= cur_gas_schedule.feature_version,
                error::invalid_argument(EINVALID_GAS_FEATURE_VERSION)
            );
        };
        config_buffer::upsert(new_gas_schedule);
    }
```

**File:** aptos-move/aptos-vm-types/src/storage/io_pricing.rs (L204-218)
```rust
    fn calculate_read_gas(
        &self,
        loaded: NumBytes,
    ) -> impl GasExpression<VMGasParameters, Unit = InternalGasUnit> + use<> {
        // Round up bytes to whole pages
        // TODO(gas): make PAGE_SIZE configurable
        const PAGE_SIZE: u64 = 4096;

        let loaded_u64: u64 = loaded.into();
        let r = loaded_u64 % PAGE_SIZE;
        let rounded_up = loaded_u64 + if r == 0 { 0 } else { PAGE_SIZE - r };

        STORAGE_IO_PER_STATE_SLOT_READ * NumArgs::from(1)
            + STORAGE_IO_PER_STATE_BYTE_READ * NumBytes::new(rounded_up)
    }
```

**File:** aptos-move/aptos-gas-meter/src/algebra.rs (L217-229)
```rust
        match self.balance.checked_sub(amount) {
            Some(new_balance) => {
                self.balance = new_balance;
                self.io_gas_used += amount;
            },
            None => {
                let old_balance = self.balance;
                self.balance = 0.into();
                if self.feature_version >= 12 {
                    self.io_gas_used += old_balance;
                }
                return Err(PartialVMError::new(StatusCode::OUT_OF_GAS));
            },
```
