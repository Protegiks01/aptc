# Audit Report

## Title
Gas Overcharging for vector<u16>, vector<u32>, and vector<u256> in Equality Operations Due to Missing DerefVisitor Overrides

## Summary
The `DerefVisitor` in the gas metering system lacks specialized overrides for `visit_vec_u16()`, `visit_vec_u32()`, and `visit_vec_u256()` methods, causing these vector types to fall back to default trait implementations that charge 10-20x more gas than intended during equality comparisons (`Eq`/`Neq` bytecode instructions) and the native `compare()` function.

## Finding Description

The Move VM gas metering system uses a visitor pattern to calculate abstract value sizes. The vulnerability occurs in the interaction between two components:

**1. AbstractValueSizeVisitor with correct specialized implementations:** [1](#0-0) 

These implementations correctly charge `vector_base + per_type_packed * length` where per_u16_packed=2, per_u32_packed=4, per_u256_packed=32.

**2. DerefVisitor missing specialized overrides:** [2](#0-1) 

The TODO comment at line 129 explicitly acknowledges this missing functionality. The `deref_visitor_delegate_simple!` macro does NOT include `visit_vec_u16`, `visit_vec_u32`, or `visit_vec_u256`.

**3. Default trait implementations cause overcharge:** [3](#0-2) 

These default implementations call `visit_vec()` (40 units) then loop through each element calling `visit_u16/u32/u256()` (40 units each), resulting in 40 + 40N total cost instead of the correct 40 + 2N/4N/32N.

**4. Equality operations use abstract_value_size_dereferenced():** [4](#0-3) 

Both `charge_eq()` and `charge_neq()` use `abstract_value_size_dereferenced()`, which creates a DerefVisitor wrapper around AbstractValueSizeVisitor.

**5. Native compare function also affected:** [5](#0-4) 

The native compare function uses `abs_val_size_dereferenced()` for gas charging.

**Gas parameter values:** [6](#0-5) 

## Impact Explanation

This is a **MEDIUM severity** vulnerability per Aptos Bug Bounty criteria, not HIGH as originally claimed:

**Why NOT HIGH:**
- Does NOT cause validator node slowdowns (overcharging doesn't slow computation)
- Does NOT cause API crashes
- All validators compute the same (incorrect) gas amount, so no consensus split occurs

**Why MEDIUM ("Limited Protocol Violations" + "Limited Funds Loss"):**

1. **Protocol Violation**: The implementation violates the gas schedule specification defined in the gas parameters. The system charges 10-20x more than the specified gas costs for these vector types.

2. **Limited Financial Loss**: Users overpay for gas when performing equality comparisons on vectors of u16/u32/u256. For a vector of 1,000 u16 elements:
   - Correct: 40 + 2×1,000 = 2,040 abstract units
   - Actual: 40 + 40×1,000 = 40,040 abstract units (19.6x overcharge)
   - With EQ_PER_ABS_VAL_UNIT multiplier and both operands: ~1,121,487 vs ~57,487 internal gas

3. **Transaction Failures**: Excessive gas consumption can cause transactions to unexpectedly exceed gas limits, resulting in failed transactions and lost gas fees.

4. **Scope Limited**: Only affects three specific vector types (u16, u32, u256) introduced in feature version 5, not all vector types.

## Likelihood Explanation

**High Likelihood of Trigger (but uncertain real-world frequency):**
- Any user can trigger by submitting Move transactions with equality comparisons on vector<u16>, vector<u32>, or vector<u256>
- No special privileges or complex setup required
- Affects both Move bytecode equality instructions and the standard library `std::compare::compare` function
- Issue exists in production code

**Uncertain Real-World Impact:**
- These vector types (u16, u32, u256) were added in feature version 5 and may not be widely used yet
- Other vector types (u8, u64, u128, bool, address, signed integers) are NOT affected as DerefVisitor correctly overrides their methods

## Recommendation

Add the missing specialized overrides to `DerefVisitor` in `misc.rs`:

```rust
impl<V> ValueVisitor for DerefVisitor<V>
where
    V: ValueVisitor,
{
    deref_visitor_delegate_simple!(
        // ... existing delegates ...
        [visit_vec_u16, &[u16]],
        [visit_vec_u32, &[u32]],
        [visit_vec_u256, &[U256]],
    );
    // ... rest of implementation ...
}
```

This will ensure these vector types use the specialized AbstractValueSizeVisitor implementations with correct gas costs.

## Proof of Concept

The following Move test would demonstrate the overcharge (conceptual - requires access to gas introspection):

```move
#[test]
fun test_vector_u16_equality_gas_overcharge() {
    let v1: vector<u16> = vector[];
    let v2: vector<u16> = vector[];
    
    // Fill vectors with 1000 elements
    let i = 0;
    while (i < 1000) {
        vector::push_back(&mut v1, (i as u16));
        vector::push_back(&mut v2, (i as u16));
        i = i + 1;
    };
    
    // This equality comparison will be charged ~1,121,487 internal gas units
    // instead of the correct ~57,487 units (19.5x overcharge)
    let _ = (v1 == v2);
}
```

**Notes:**
- The vulnerability is confirmed by code inspection and the explicit TODO comment acknowledging the missing functionality
- This is a legitimate bug with financial impact, but classified as MEDIUM severity based on Aptos Bug Bounty criteria
- The overcharge factors are: vector<u16>=20x, vector<u32>=10x, vector<u256>=1.25x
- All validators compute the same incorrect gas, preventing consensus issues but causing user financial loss

### Citations

**File:** aptos-move/aptos-gas-schedule/src/gas_schedule/misc.rs (L27-73)
```rust
crate::gas_schedule::macros::define_gas_parameters!(
    AbstractValueSizeGasParameters,
    "misc.abs_val",
    VMGasParameters => .misc.abs_val,
    [
        // abstract value size
        [u8: AbstractValueSize, "u8", 40],
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
        [per_u64_packed: AbstractValueSizePerArg, "per_u64_packed", 8],
        [per_u128_packed: AbstractValueSizePerArg, "per_u128_packed", 16],
        [per_u256_packed: AbstractValueSizePerArg, { 5.. => "per_u256_packed" }, 32],
        [per_i8_packed: AbstractValueSizePerArg, { RELEASE_V1_38.. => "per_i8_packed" }, 1],
        [per_i16_packed: AbstractValueSizePerArg, { RELEASE_V1_38.. => "per_i16_packed" }, 2],
        [per_i32_packed: AbstractValueSizePerArg, { RELEASE_V1_38.. => "per_i32_packed" }, 4],
        [per_i64_packed: AbstractValueSizePerArg, { RELEASE_V1_38.. => "per_i64_packed" }, 8],
        [per_i128_packed: AbstractValueSizePerArg, { RELEASE_V1_38.. => "per_i128_packed" }, 16],
        [per_i256_packed: AbstractValueSizePerArg, { RELEASE_V1_38.. => "per_i256_packed" }, 32],
        [
            per_bool_packed: AbstractValueSizePerArg,
            "per_bool_packed",
            1
        ],
        [
            per_address_packed: AbstractValueSizePerArg,
            "per_address_packed",
            32
        ],
    ]
```

**File:** aptos-move/aptos-gas-schedule/src/gas_schedule/misc.rs (L113-141)
```rust
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
```

**File:** aptos-move/aptos-gas-schedule/src/gas_schedule/misc.rs (L346-389)
```rust
    fn visit_vec_u16(&mut self, depth: u64, vals: &[u16]) -> PartialVMResult<()> {
        self.check_depth(depth)?;
        self.size +=
            self.params.vector + self.params.per_u16_packed * NumArgs::new(vals.len() as u64);
        Ok(())
    }

    #[inline]
    fn visit_vec_u32(&mut self, depth: u64, vals: &[u32]) -> PartialVMResult<()> {
        self.check_depth(depth)?;
        self.size +=
            self.params.vector + self.params.per_u32_packed * NumArgs::new(vals.len() as u64);
        Ok(())
    }

    #[inline]
    fn visit_vec_u64(&mut self, depth: u64, vals: &[u64]) -> PartialVMResult<()> {
        self.check_depth(depth)?;
        let mut size = self.params.per_u64_packed * NumArgs::new(vals.len() as u64);
        if self.feature_version >= 3 {
            size += self.params.vector;
        }
        self.size += size;
        Ok(())
    }

    #[inline]
    fn visit_vec_u128(&mut self, depth: u64, vals: &[u128]) -> PartialVMResult<()> {
        self.check_depth(depth)?;
        let mut size = self.params.per_u128_packed * NumArgs::new(vals.len() as u64);
        if self.feature_version >= 3 {
            size += self.params.vector;
        }
        self.size += size;
        Ok(())
    }

    #[inline]
    fn visit_vec_u256(&mut self, depth: u64, vals: &[U256]) -> PartialVMResult<()> {
        self.check_depth(depth)?;
        self.size +=
            self.params.vector + self.params.per_u256_packed * NumArgs::new(vals.len() as u64);
        Ok(())
    }
```

**File:** third_party/move/move-vm/types/src/views.rs (L250-292)
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
```

**File:** aptos-move/aptos-gas-meter/src/meter.rs (L398-420)
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

    #[inline]
    fn charge_neq(&mut self, lhs: impl ValueView, rhs: impl ValueView) -> PartialVMResult<()> {
        let abs_val_params = &self.vm_gas_params().misc.abs_val;

        let cost = NEQ_BASE
            + NEQ_PER_ABS_VAL_UNIT
                * (abs_val_params.abstract_value_size_dereferenced(lhs, self.feature_version())?
                    + abs_val_params
                        .abstract_value_size_dereferenced(rhs, self.feature_version())?);

        self.algebra.charge_execution(cost)
```

**File:** aptos-move/framework/move-stdlib/src/natives/cmp.rs (L36-52)
```rust
fn native_compare(
    context: &mut SafeNativeContext,
    _ty_args: &[Type],
    args: VecDeque<Value>,
) -> SafeNativeResult<SmallVec<[Value; 1]>> {
    debug_assert!(args.len() == 2);
    if args.len() != 2 {
        return Err(SafeNativeError::InvariantViolation(PartialVMError::new(
            StatusCode::UNKNOWN_INVARIANT_VIOLATION_ERROR,
        )));
    }

    let cost = CMP_COMPARE_BASE
        + CMP_COMPARE_PER_ABS_VAL_UNIT
            * (context.abs_val_size_dereferenced(&args[0])?
                + context.abs_val_size_dereferenced(&args[1])?);
    context.charge(cost)?;
```
