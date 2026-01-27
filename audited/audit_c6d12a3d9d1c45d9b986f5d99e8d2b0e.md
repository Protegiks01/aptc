# Audit Report

## Title
Inconsistent Gas Metering Due to Missing Method Overrides in DerefVisitor for Vec<u16>, Vec<u32>, and Vec<u256>

## Summary
The `DerefVisitor` wrapper in the gas scheduling system fails to override `visit_vec_u16`, `visit_vec_u32`, and `visit_vec_u256` methods, causing it to fall back to default trait implementations that charge significantly different gas amounts compared to the intended custom implementations. This creates inconsistent gas metering for dereferenced vector comparisons. [1](#0-0) 

## Finding Description

The `ValueVisitor` trait provides default implementations for vector visiting methods that both call `visit_vec` and iterate through each element: [2](#0-1) 

However, `AbstractValueSizeVisitor` overrides these with optimized implementations that charge based on packed size parameters: [3](#0-2) 

The `DerefVisitor` wrapper delegates most methods but explicitly omits `visit_vec_u16`, `visit_vec_u32`, and `visit_vec_u256` (see TODO comment): [4](#0-3) 

When `abstract_value_size_dereferenced` is called (used in equality/inequality comparisons), it wraps `AbstractValueSizeVisitor` with `DerefVisitor`: [5](#0-4) 

This is invoked in gas charging for equality operations: [6](#0-5) 

**Gas Charging Discrepancy:**
- Gas parameters show `u16 = 40` (scalar) vs `per_u16_packed = 2` (vector element): [7](#0-6) 

- Default implementation charges: `vector (40) + u16 (40) × length`
- Custom implementation charges: `vector (40) + per_u16_packed (2) × length`

For a `Vec<u16>` with 100 elements:
- Default path: 40 + (40 × 100) = **4,040 gas units**
- Custom path: 40 + (2 × 100) = **240 gas units**
- **Overcharge factor: 16.8x**

## Impact Explanation

While this represents a significant gas metering inconsistency, it does **NOT** meet the criteria for a security vulnerability under the Aptos bug bounty program:

1. **No Consensus Violation**: All validators execute identical code with identical feature versions, so all nodes charge the same (incorrect) amount. Deterministic execution is preserved.

2. **No Economic Exploit**: The bug **overcharges** users, not undercharges. An attacker cannot drain resources for free or steal funds - they would pay **more** gas than intended, making this economically unfavorable for exploitation.

3. **No DOS Capability**: While an attacker could create transactions with large Vec<u16> comparisons, they still pay the overcharged gas, preventing free resource exhaustion.

4. **Limited User Impact**: Only affects specific operations (equality/inequality comparisons on references to Vec<u16>/Vec<u32>/Vec<u256>), which are likely rare in practice.

This is a **correctness bug** affecting user experience and fair pricing, but not a **security vulnerability** that enables theft, consensus breaks, or protocol violations as defined in the bug bounty categories.

## Likelihood Explanation

The bug triggers whenever:
1. A transaction performs equality (`==`) or inequality (`!=`) comparisons
2. On dereferenced values of types Vec<u16>, Vec<u32>, or Vec<u256>
3. With non-trivial vector lengths

However, since feature version 5 introduced u16/u32/u256 types, these comparisons may be relatively uncommon in deployed smart contracts. The likelihood of user impact exists but is mitigated by limited usage of these specific vector types in comparison operations.

## Recommendation

Add the missing method overrides to `DerefVisitor` to properly delegate to the inner visitor:

```rust
impl<V> ValueVisitor for DerefVisitor<V>
where
    V: ValueVisitor,
{
    deref_visitor_delegate_simple!(
        // ... existing delegations ...
        [visit_vec_u16, &[u16]],  // ADD THIS
        [visit_vec_u32, &[u32]],  // ADD THIS  
        [visit_vec_u256, &[move_core_types::int256::U256]],  // ADD THIS
        // ... rest of delegations ...
    );
    // ... rest of implementation ...
}
```

This ensures consistent gas charging whether values are accessed directly or through dereference.

## Proof of Concept

```move
module 0x1::gas_inconsistency_test {
    use std::vector;
    
    public entry fun test_vec_u16_comparison() {
        // Create two Vec<u16> with 100 elements
        let v1 = vector::empty<u16>();
        let v2 = vector::empty<u16>();
        let i = 0;
        while (i < 100) {
            vector::push_back(&mut v1, (i as u16));
            vector::push_back(&mut v2, (i as u16));
            i = i + 1;
        };
        
        // This comparison will be overcharged by ~16.8x
        // due to DerefVisitor falling back to default implementation
        assert!(v1 == v2, 0);
    }
}
```

## Notes

After rigorous validation against the Aptos bug bounty criteria, this issue does **not** qualify as a security vulnerability because it:
- Maintains consensus (deterministic across all validators)
- Overcharges rather than undercharges (no economic exploit)
- Cannot be leveraged for DOS or fund theft

However, it remains a high-priority **correctness bug** that should be fixed to ensure fair and accurate gas pricing for users. I recommend reporting this through Aptos's standard bug reporting channels rather than the security bounty program.

### Citations

**File:** aptos-move/aptos-gas-schedule/src/gas_schedule/misc.rs (L34-53)
```rust
        [u16: AbstractValueSize, { 5.. => "u16" }, 40],
        [u32: AbstractValueSize, { 5.. => "u32" }, 40],
        [u64: AbstractValueSize, "u64", 40],
        [u128: AbstractValueSize, "u128", 40],
        [u256: AbstractValueSize, { 5.. => "u256" }, 40],
        [i8: AbstractValueSize, { RELEASE_V1_38.. => "i8" }, 40],
        [i16: AbstractValueSize, { RELEASE_V1_38.. => "i16" }, 40],
        [i32: AbstractValueSize, { RELEASE_V1_38.. => "i32" }, 40],
        [i64: AbstractValueSize, { RELEASE_V1_38.. => "i64" }, 40],
        [i128: AbstractValueSize, { RELEASE_V1_38.. => "i128" }, 40],
        [i256: AbstractValueSize, { RELEASE_V1_38.. => "i256" }, 40],
        [bool: AbstractValueSize, "bool", 40],
        [address: AbstractValueSize, "address", 40],
        [struct_: AbstractValueSize, "struct", 40],
        [closure: AbstractValueSize, { RELEASE_V1_33.. => "closure" }, 40],
        [vector: AbstractValueSize, "vector", 40],
        [reference: AbstractValueSize, "reference", 40],
        [per_u8_packed: AbstractValueSizePerArg, "per_u8_packed", 1],
        [per_u16_packed: AbstractValueSizePerArg, { 5.. => "per_u16_packed" }, 2],
        [per_u32_packed: AbstractValueSizePerArg, { 5.. => "per_u32_packed" }, 4],
```

**File:** aptos-move/aptos-gas-schedule/src/gas_schedule/misc.rs (L109-164)
```rust
impl<V> ValueVisitor for DerefVisitor<V>
where
    V: ValueVisitor,
{
    deref_visitor_delegate_simple!(
        [visit_delayed, DelayedFieldID],
        [visit_u8, u8],
        [visit_u16, u16],
        [visit_u32, u32],
        [visit_u64, u64],
        [visit_u128, u128],
        [visit_u256, &U256],
        [visit_i8, i8],
        [visit_i16, i16],
        [visit_i32, i32],
        [visit_i64, i64],
        [visit_i128, i128],
        [visit_i256, &I256],
        [visit_bool, bool],
        [visit_address, &AccountAddress],
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

    #[inline]
    fn visit_struct(&mut self, depth: u64, len: usize) -> PartialVMResult<bool> {
        self.inner.visit_struct(depth - self.offset as u64, len)
    }

    #[inline]
    fn visit_vec(&mut self, depth: u64, len: usize) -> PartialVMResult<bool> {
        self.inner.visit_vec(depth - self.offset as u64, len)
    }

    #[inline]
    fn visit_ref(&mut self, depth: u64, _is_global: bool) -> PartialVMResult<bool> {
        assert_eq!(depth, 0, "There shouldn't be inner refs");
        self.offset = 1;
        Ok(true)
    }

    #[inline]
    fn visit_closure(&mut self, depth: u64, len: usize) -> PartialVMResult<bool> {
        self.inner.visit_closure(depth, len)
    }
}
```

**File:** aptos-move/aptos-gas-schedule/src/gas_schedule/misc.rs (L346-351)
```rust
    fn visit_vec_u16(&mut self, depth: u64, vals: &[u16]) -> PartialVMResult<()> {
        self.check_depth(depth)?;
        self.size +=
            self.params.vector + self.params.per_u16_packed * NumArgs::new(vals.len() as u64);
        Ok(())
    }
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

**File:** third_party/move/move-vm/types/src/views.rs (L250-264)
```rust
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
