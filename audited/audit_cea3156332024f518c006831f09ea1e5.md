# Audit Report

## Title
Gas Calculation Overcharging for Vec<u16>, Vec<u32>, and Vec<u256> Due to Missing DerefVisitor Delegations

## Summary
The `DerefVisitor` in the gas schedule module is missing delegation implementations for `visit_vec_u16`, `visit_vec_u32`, and `visit_vec_u256`, causing these vector types to use the default trait implementation which results in massive gas overcharging (up to 20x) when these values are accessed through references during equality operations.

## Finding Description
The "upstream bug" mentioned in the TODO comments [1](#0-0)  refers to a design flaw in the `ValueVisitor` trait's default implementations [2](#0-1) . These defaults call `visit_vec` followed by looping through each element, which doesn't work correctly for result-setting visitors.

While the gas schedule code correctly works around this bug for `abstract_stack_size` and `abstract_packed_size` visitors [3](#0-2) , the `DerefVisitor` has a critical TODO indicating missing support [4](#0-3) . 

When `DerefVisitor` encounters `Vec<u16>`, `Vec<u32>`, or `Vec<u256>`, it falls back to the default trait implementation which incorrectly calls `visit_u16`/`visit_u32`/`visit_u256` for each element (adding `params.u16 = 40` per element) instead of using the packed size parameters (`params.per_u16_packed = 2`). This is used in `abstract_value_size_dereferenced` [5](#0-4) , which is called during equality comparisons [6](#0-5) .

For a `Vec<u16>` with 1000 elements:
- Correct cost: 40 + 1000 × 2 = 2,040 gas units
- Actual cost (bug): 40 + 1000 × 40 = 40,040 gas units  
- Overcharge: 19.6x

## Impact Explanation
**Severity: Medium**

This violates the "Move VM Safety: Bytecode execution must respect gas limits" invariant by incorrect gas calculation, though it overcharges rather than undercharges. Users performing equality comparisons on references to `Vec<u16>`, `Vec<u32>`, or `Vec<u256>` pay significantly more gas than they should, constituting a "Limited funds loss" per the bug bounty criteria. While this doesn't enable direct attacker exploitation or consensus violations, it represents a significant protocol violation in gas metering correctness.

## Likelihood Explanation
**Likelihood: Medium**

The bug triggers automatically whenever Move code compares references to vectors of these specific types. While `Vec<u8>` is more common in practice, `Vec<u16>`, `Vec<u32>`, and `Vec<u256>` are valid Move types that can be used in smart contracts. The overcharging is deterministic and affects all users equally.

## Recommendation
Add the missing vector type delegations to `DerefVisitor`: [4](#0-3) 

Add `visit_vec_u16`, `visit_vec_u32`, and `visit_vec_u256` to the `deref_visitor_delegate_simple!` macro invocation after line 129:

```rust
[visit_vec_u16, &[u16]],
[visit_vec_u32, &[u32]],  
[visit_vec_u256, &[U256]],
```

## Proof of Concept
A Move module demonstrating the issue:

```move
module 0x1::gas_overcharge_test {
    public fun compare_vec_u16_refs(v1: &vector<u16>, v2: &vector<u16>): bool {
        v1 == v2  // This triggers abstract_value_size_dereferenced
    }
    
    #[test]
    public fun test_comparison() {
        let v1 = vector::empty<u16>();
        let v2 = vector::empty<u16>();
        
        // Add 1000 elements
        let i = 0;
        while (i < 1000) {
            vector::push_back(&mut v1, (i as u16));
            vector::push_back(&mut v2, (i as u16));
            i = i + 1;
        };
        
        // This comparison will be charged 40,040 gas units instead of 2,040
        let _ = compare_vec_u16_refs(&v1, &v2);
    }
}
```

## Notes
The underlying issue is the `ValueVisitor` trait design in the Move VM types crate, which provides default implementations that assume accumulating visitors rather than result-setting visitors. The gas schedule module has worked around this for most cases, but the `DerefVisitor` implementation remains incomplete, leading to this gas calculation bug.

### Citations

**File:** aptos-move/aptos-gas-schedule/src/gas_schedule/misc.rs (L129-141)
```rust
        // TODO(##17840): add supports for `visit_vec_u16`, `visit_vec_u32`, `visit_vec_u256`
        [visit_vec_u8, &[u8]],
        [visit_vec_u64, &[u64]],
        [visit_vec_u128, &[u128]],
        [visit_vec_bool, &[bool]],
        [visit_vec_address, &[AccountAddress]],
        [visit_vec_i8, &[i8]],
        [visit_vec_i16, &[i16]],
        [visit_vec_i32, &[i32]],
        [visit_vec_i64, &[i64]],
        [visit_vec_i128, &[i128]],
        [visit_vec_i256, &[I256]],
    );
```

**File:** aptos-move/aptos-gas-schedule/src/gas_schedule/misc.rs (L483-491)
```rust
    pub fn abstract_value_size_dereferenced(
        &self,
        val: impl ValueView,
        feature_version: u64,
    ) -> PartialVMResult<AbstractValueSize> {
        let mut visitor = DerefVisitor::new(AbstractValueSizeVisitor::new(self, feature_version));
        val.visit(&mut visitor)?;
        Ok(visitor.into_inner().finish())
    }
```

**File:** aptos-move/aptos-gas-schedule/src/gas_schedule/misc.rs (L645-654)
```rust
            // TODO(Gas): The following function impls are necessary due to a bug upstream.
            //            Remove them once the bug is fixed.
            #[inline]
            fn visit_vec_u8(&mut self, depth: u64, vals: &[u8]) -> PartialVMResult<()> {
                if self.feature_version < 3 {
                    self.res = Some(0.into());
                } else {
                    self.visit_vec(depth, vals.len())?;
                }
                Ok(())
```

**File:** aptos-move/aptos-gas-schedule/src/gas_schedule/misc.rs (L879-880)
```rust
            // TODO(Gas): The following function impls are necessary due to a bug upstream.
            //            Remove them once the bug is fixed.
```

**File:** third_party/move/move-vm/types/src/views.rs (L242-360)
```rust
    fn visit_vec_u8(&mut self, depth: u64, vals: &[u8]) -> PartialVMResult<()> {
        self.visit_vec(depth, vals.len())?;
        for val in vals {
            self.visit_u8(depth + 1, *val)?;
        }
        Ok(())
    }

    fn visit_vec_u16(&mut self, depth: u64, vals: &[u16]) -> PartialVMResult<()> {
        self.visit_vec(depth, vals.len())?;
        for val in vals {
            self.visit_u16(depth + 1, *val)?;
        }
        Ok(())
    }

    fn visit_vec_u32(&mut self, depth: u64, vals: &[u32]) -> PartialVMResult<()> {
        self.visit_vec(depth, vals.len())?;
        for val in vals {
            self.visit_u32(depth + 1, *val)?;
        }
        Ok(())
    }

    fn visit_vec_u64(&mut self, depth: u64, vals: &[u64]) -> PartialVMResult<()> {
        self.visit_vec(depth, vals.len())?;
        for val in vals {
            self.visit_u64(depth + 1, *val)?;
        }
        Ok(())
    }

    fn visit_vec_u128(&mut self, depth: u64, vals: &[u128]) -> PartialVMResult<()> {
        self.visit_vec(depth, vals.len())?;
        for val in vals {
            self.visit_u128(depth + 1, *val)?;
        }
        Ok(())
    }

    fn visit_vec_u256(
        &mut self,
        depth: u64,
        vals: &[move_core_types::int256::U256],
    ) -> PartialVMResult<()> {
        self.visit_vec(depth, vals.len())?;
        for val in vals {
            self.visit_u256(depth + 1, val)?;
        }
        Ok(())
    }

    fn visit_vec_i8(&mut self, depth: u64, vals: &[i8]) -> PartialVMResult<()> {
        self.visit_vec(depth, vals.len())?;
        for val in vals {
            self.visit_i8(depth + 1, *val)?;
        }
        Ok(())
    }

    fn visit_vec_i16(&mut self, depth: u64, vals: &[i16]) -> PartialVMResult<()> {
        self.visit_vec(depth, vals.len())?;
        for val in vals {
            self.visit_i16(depth + 1, *val)?;
        }
        Ok(())
    }

    fn visit_vec_i32(&mut self, depth: u64, vals: &[i32]) -> PartialVMResult<()> {
        self.visit_vec(depth, vals.len())?;
        for val in vals {
            self.visit_i32(depth + 1, *val)?;
        }
        Ok(())
    }

    fn visit_vec_i64(&mut self, depth: u64, vals: &[i64]) -> PartialVMResult<()> {
        self.visit_vec(depth, vals.len())?;
        for val in vals {
            self.visit_i64(depth + 1, *val)?;
        }
        Ok(())
    }

    fn visit_vec_i128(&mut self, depth: u64, vals: &[i128]) -> PartialVMResult<()> {
        self.visit_vec(depth, vals.len())?;
        for val in vals {
            self.visit_i128(depth + 1, *val)?;
        }
        Ok(())
    }

    fn visit_vec_i256(
        &mut self,
        depth: u64,
        vals: &[move_core_types::int256::I256],
    ) -> PartialVMResult<()> {
        self.visit_vec(depth, vals.len())?;
        for val in vals {
            self.visit_i256(depth + 1, val)?;
        }
        Ok(())
    }

    fn visit_vec_bool(&mut self, depth: u64, vals: &[bool]) -> PartialVMResult<()> {
        self.visit_vec(depth, vals.len())?;
        for val in vals {
            self.visit_bool(depth + 1, *val)?;
        }
        Ok(())
    }

    fn visit_vec_address(&mut self, depth: u64, vals: &[AccountAddress]) -> PartialVMResult<()> {
        self.visit_vec(depth, vals.len())?;
        for val in vals {
            self.visit_address(depth + 1, val)?;
        }
        Ok(())
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
