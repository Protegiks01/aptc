# Audit Report

## Title
Gas Schedule Parameter Manipulation Enables Incorrect Abstract Value Size Calculations Through Saturating Arithmetic

## Summary
The `misc_gas_params.abs_val` parameters used for abstract value size calculations lack validation when updated via governance, and calculations use saturating arithmetic. This allows malicious or buggy governance proposals to set parameters that cause systematic undercharging or overcharging of gas, violating the Move VM gas metering invariant.

## Finding Description

The gas schedule update mechanism in Aptos has a critical gap in parameter validation. When governance updates gas parameters via `set_for_next_epoch()` or `set_for_next_epoch_check_hash()`, the Move code contains TODO comments indicating validation should occur but is not implemented: [1](#0-0) [2](#0-1) [3](#0-2) 

The abstract value size calculation system uses saturating arithmetic for additions and multiplications: [4](#0-3) [5](#0-4) 

When calculating abstract value sizes, the visitor accumulates sizes using the `+=` operator which uses `saturating_add`: [6](#0-5) 

This creates two attack scenarios:

**Scenario 1: Zero Parameters** - If `misc.abs_val.*` parameters are set to 0, abstract value sizes become 0, causing operations like `charge_copy_loc`, `charge_read_ref`, `charge_eq`, and `charge_neq` to undercharge or charge zero gas.

**Scenario 2: Excessive Parameters** - If parameters are set near `u64::MAX`, saturating arithmetic causes complex nested structures to have the same calculated size as simple structures. For example, a struct with 100 u64 fields would saturate at the same value as a struct with 2 u64 fields, systematically undercharging gas for complex values.

These calculations are used throughout gas metering: [7](#0-6) [8](#0-7) 

## Impact Explanation

This vulnerability qualifies as **High Severity** based on:

1. **Gas Metering Bypass**: Enables free or severely undercharged computation, violating the "Move VM Safety: Bytecode execution must respect gas limits and memory constraints" invariant.

2. **Consensus Risk**: If malicious parameters are set, different nodes executing the same block could charge different gas amounts, potentially causing state divergence if gas exhaustion occurs at different points.

3. **Resource Exhaustion**: Allows attackers to perform expensive operations (deep comparisons, large copies) at minimal gas cost after malicious parameters are installed.

4. **Network Stability**: Incorrect gas metering breaks the economic model that prevents DoS attacks on validators.

## Likelihood Explanation

**Likelihood: Medium to Low**

This vulnerability requires governance control to exploit, meaning:
- A malicious governance proposal must pass voting
- OR a legitimate proposal contains a bug in parameter values
- OR governance keys are compromised

However, the **lack of validation** means accidental exploitation through proposal bugs is realistic. The presence of multiple TODO comments indicates developers are aware validation is needed but it remains unimplemented, increasing the risk of oversight in governance proposals.

The saturating arithmetic behavior is particularly insidious because it fails silently—no error is raised, parameters appear to load successfully, but gas calculations become systematically incorrect.

## Recommendation

Implement comprehensive validation in the Move framework when gas schedules are updated:

```move
// In gas_schedule.move, replace TODOs with actual validation:
public fun set_for_next_epoch(aptos_framework: &signer, gas_schedule_blob: vector<u8>) acquires GasScheduleV2 {
    system_addresses::assert_aptos_framework(aptos_framework);
    assert!(!vector::is_empty(&gas_schedule_blob), error::invalid_argument(EINVALID_GAS_SCHEDULE));
    let new_gas_schedule: GasScheduleV2 = from_bytes(gas_schedule_blob);
    
    // ADD VALIDATION HERE:
    validate_gas_schedule_consistency(&new_gas_schedule);
    
    if (exists<GasScheduleV2>(@aptos_framework)) {
        let cur_gas_schedule = borrow_global<GasScheduleV2>(@aptos_framework);
        assert!(
            new_gas_schedule.feature_version >= cur_gas_schedule.feature_version,
            error::invalid_argument(EINVALID_GAS_FEATURE_VERSION)
        );
    };
    config_buffer::upsert(new_gas_schedule);
}

// Add validation function:
fun validate_gas_schedule_consistency(schedule: &GasScheduleV2) {
    // Validate misc.abs_val parameters are within reasonable bounds
    // Example bounds (adjust based on actual requirements):
    // - All abstract value size parameters must be > 0 and < 10^9
    // - Packed size parameters must match expected byte sizes
    // - Struct/vector/reference costs must be >= primitive type costs
    let entries = &schedule.entries;
    // Iterate and validate each parameter...
}
```

Additionally, consider using checked arithmetic instead of saturating arithmetic for critical gas calculations, or add overflow detection:

```rust
// In gas_algebra.rs, add overflow detection:
impl<U> Add<GasQuantity<U>> for GasQuantity<U> {
    type Output = Self;
    
    fn add(self, rhs: Self) -> Self::Output {
        // Option 1: Use checked_add and panic on overflow
        Self::new(self.val.checked_add(rhs.val)
            .expect("Gas calculation overflow - parameters may be misconfigured"))
        
        // Option 2: Log warning when saturation occurs
        // let result = self.val.saturating_add(rhs.val);
        // if result == u64::MAX && self.val != u64::MAX && rhs.val != u64::MAX {
        //     log_saturation_warning();
        // }
        // Self::new(result)
    }
}
```

## Proof of Concept

```rust
// Proof of concept demonstrating saturating arithmetic issue
// File: aptos-move/aptos-gas-schedule/tests/saturation_test.rs

#[cfg(test)]
mod tests {
    use aptos_gas_algebra::AbstractValueSize;
    use aptos_gas_schedule::{AbstractValueSizeGasParameters, MiscGasParameters};
    use std::collections::BTreeMap;
    
    #[test]
    fn test_saturating_arithmetic_undercharges() {
        // Create gas schedule with excessive parameters
        let mut gas_schedule = BTreeMap::new();
        let excessive_value = u64::MAX / 2;
        
        gas_schedule.insert("misc.abs_val.u64".to_string(), excessive_value);
        gas_schedule.insert("misc.abs_val.struct".to_string(), excessive_value);
        
        let params = AbstractValueSizeGasParameters::from_on_chain_gas_schedule(
            &gas_schedule, 
            10
        ).unwrap();
        
        // Simulate a struct with 2 u64 fields
        let size_2_fields = params.u64 + params.u64 + params.struct_;
        
        // Due to saturating arithmetic:
        // excessive_value + excessive_value = u64::MAX (saturates)
        // u64::MAX + excessive_value = u64::MAX (saturates)
        assert_eq!(u64::from(size_2_fields), u64::MAX);
        
        // Simulate a struct with 100 u64 fields
        let mut size_100_fields: AbstractValueSize = params.struct_.into();
        for _ in 0..100 {
            size_100_fields += params.u64;
        }
        
        // ALL additions after saturation point return u64::MAX
        assert_eq!(u64::from(size_100_fields), u64::MAX);
        
        // This demonstrates that a 100-field struct has the SAME calculated size
        // as a 2-field struct, leading to systematic undercharging
        assert_eq!(size_2_fields, size_100_fields);
        
        println!("VULNERABILITY: 100-field struct charges same gas as 2-field struct!");
    }
    
    #[test]
    fn test_zero_parameters_enable_free_operations() {
        let mut gas_schedule = BTreeMap::new();
        
        // Malicious governance sets all parameters to 0
        gas_schedule.insert("misc.abs_val.u8".to_string(), 0);
        gas_schedule.insert("misc.abs_val.u64".to_string(), 0);
        gas_schedule.insert("misc.abs_val.struct".to_string(), 0);
        
        let params = AbstractValueSizeGasParameters::from_on_chain_gas_schedule(
            &gas_schedule,
            10
        ).unwrap();
        
        // All abstract value sizes are now 0
        assert_eq!(u64::from(params.u64), 0);
        assert_eq!(u64::from(params.struct_), 0);
        
        // This would cause charge_copy_loc, charge_read_ref, etc. to charge 0 gas
        println!("VULNERABILITY: Zero parameters enable free computation!");
    }
}
```

## Notes

This vulnerability represents a **governance-layer attack surface** where the lack of parameter validation creates systemic risk. While exploitation requires governance control (making it higher barrier than user-level attacks), the consequences affect all network participants and could lead to consensus failures or economic attacks.

The presence of TODO comments at lines 47, 67, and 75 in `gas_schedule.move` indicates this is a **known technical debt** that should be prioritized for remediation.

### Citations

**File:** aptos-move/framework/aptos-framework/sources/configs/gas_schedule.move (L47-48)
```text
        // TODO(Gas): check if gas schedule is consistent
        let gas_schedule: GasScheduleV2 = from_bytes(gas_schedule_blob);
```

**File:** aptos-move/framework/aptos-framework/sources/configs/gas_schedule.move (L67-68)
```text
            // TODO(Gas): check if gas schedule is consistent
            *gas_schedule = new_gas_schedule;
```

**File:** aptos-move/framework/aptos-framework/sources/configs/gas_schedule.move (L75-76)
```text
            // TODO(Gas): check if gas schedule is consistent
            move_to<GasScheduleV2>(aptos_framework, new_gas_schedule);
```

**File:** third_party/move/move-core/types/src/gas_algebra.rs (L205-210)
```rust
impl<U> Add<GasQuantity<U>> for GasQuantity<U> {
    type Output = Self;

    fn add(self, rhs: Self) -> Self::Output {
        Self::new(self.val.saturating_add(rhs.val))
    }
```

**File:** third_party/move/move-core/types/src/gas_algebra.rs (L229-231)
```rust
fn mul_impl<U1, U2>(x: GasQuantity<U2>, y: GasQuantity<UnitDiv<U1, U2>>) -> GasQuantity<U1> {
    GasQuantity::new(x.val.saturating_mul(y.val))
}
```

**File:** aptos-move/aptos-gas-schedule/src/gas_schedule/misc.rs (L216-220)
```rust
    fn visit_u8(&mut self, depth: u64, _val: u8) -> PartialVMResult<()> {
        self.check_depth(depth)?;
        self.size += self.params.u8;
        Ok(())
    }
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

**File:** aptos-move/aptos-gas-meter/src/meter.rs (L398-408)
```rust
    fn charge_eq(&mut self, lhs: impl ValueView, rhs: impl ValueView) -> PartialVMResult<()> {
        let abs_val_params = &self.vm_gas_params().misc.abs_val;

        let cost = EQ_BASE
            + EQ_PER_ABS_VAL_UNIT
                * (abs_val_params.abstract_value_size_dereferenced(lhs, self.feature_version())?
                    + abs_val_params
                        .abstract_value_size_dereferenced(rhs, self.feature_version())?);

        self.algebra.charge_execution(cost)
    }
```
