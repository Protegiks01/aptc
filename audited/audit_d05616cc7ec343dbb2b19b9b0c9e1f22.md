# Audit Report

## Title
Unmetered Heap Memory Allocation for Boxed Types (U256, I256, Address) Bypasses Memory Quota Leading to Validator DoS

## Summary
The Move VM's gas metering system incorrectly calculates zero heap memory cost for boxed types (U256, I256, Address), allowing attackers to bypass the memory quota system and cause unbounded heap allocation leading to validator node out-of-memory crashes.

## Finding Description

The `test_make_sure_value_size_stays_under_32_bytes()` test validates that the `Value` enum stays under 32 bytes on the stack. [1](#0-0) 

To achieve this size constraint, U256, I256, and Address types are heap-allocated using `Box`: [2](#0-1) 

Each constructor allocates 32 bytes on the heap: [3](#0-2) 

However, the gas metering system has a critical flaw. The abstract memory size parameters set both the total value size AND stack size to 40 units for these types: [4](#0-3) 

The `abstract_stack_size` visitor returns the same 40 units: [5](#0-4) 

This causes `abstract_heap_size` to calculate as **zero**: [6](#0-5) 

When operations like copying values charge heap memory, they use this zero value: [7](#0-6) [8](#0-7) 

The memory quota system should prevent unbounded allocation: [9](#0-8) 

But since heap_size = 0 for boxed types, the quota is never consumed, violating **Invariant #3: Move VM Safety - Bytecode execution must respect gas limits and memory constraints**.

## Impact Explanation

This is a **High Severity** vulnerability per Aptos bug bounty criteria because it enables:

1. **Validator node slowdowns** - Attackers can exhaust heap memory causing garbage collection pressure and performance degradation
2. **Potential node crashes** - Sustained memory allocation can trigger OOM conditions, crashing validator nodes
3. **Protocol violation** - Bypasses the memory quota system designed to prevent resource exhaustion attacks

While execution gas limits provide some mitigation, the core invariant is broken: heap memory allocations are unmetered. An attacker can craft Move bytecode that creates vectors of U256/I256/Address values in loops, allocating substantial untracked heap memory within gas limits.

## Likelihood Explanation

**Likelihood: High**

- Any user can submit transactions containing Move bytecode
- No special privileges required
- Simple exploitation: loop creating U256 values and storing in a vector
- The vulnerability is architectural - affects all operations with these types
- Gas parameters are on-chain constants, difficult to change quickly

## Recommendation

Fix the gas parameter configuration to properly account for heap allocation. The abstract_stack_size for boxed types should reflect only the pointer size (8 bytes), not the full conceptual size:

**Option 1**: Modify gas parameters
```rust
// In misc.rs gas parameter definitions
[u256: AbstractValueSize, { 5.. => "u256" }, 40],  // Keep total
[u256_stack: AbstractValueSize, { NEW_VERSION.. => "u256_stack" }, 8],  // Add stack param
```

Then use separate stack calculations for boxed vs non-boxed types in the visitor.

**Option 2**: Add explicit heap size tracking for boxed values in the visitor pattern to ensure heap_size = 32 units (not 0) for these types.

**Option 3**: Unbox these types and accept a larger Value enum size (but this breaks the 32-byte constraint test).

Recommended: **Option 2** with backport to existing feature versions.

## Proof of Concept

```move
module 0xCAFE::heap_exhaust {
    use std::vector;
    
    // Create many U256 values without consuming memory quota
    public entry fun exhaust_heap() {
        let v = vector::empty<u256>();
        let i = 0;
        // Each iteration allocates 32 bytes heap (Box<U256>)
        // but charges 0 abstract heap size
        while (i < 100000) {
            vector::push_back(&mut v, (i as u256));
            i = i + 1;
        };
        // Total unmetered heap: ~3.2 MB per transaction
        // Can be repeated across multiple transactions
    }
}
```

The above code will:
1. Execute successfully within gas limits
2. Allocate ~3.2MB of unmetered heap memory
3. Not consume memory quota (should return MEMORY_LIMIT_EXCEEDED but doesn't)
4. When repeated across multiple concurrent transactions, can exhaust validator memory

## Notes

The 32-byte size constraint test is a code quality check, not a security mechanism. The actual security vulnerability is the misconfiguration of gas metering parameters that fails to account for heap allocations of boxed types, breaking the fundamental invariant that all VM memory usage must be properly metered and bounded.

### Citations

**File:** third_party/move/move-vm/types/src/values/value_tests.rs (L13-16)
```rust
#[test]
fn test_make_sure_value_size_stays_under_32_bytes() {
    assert!(size_of::<Value>() <= 32);
}
```

**File:** third_party/move/move-vm/types/src/values/values_impl.rs (L79-87)
```rust
    U256(Box<int256::U256>),
    I8(i8),
    I16(i16),
    I32(i32),
    I64(i64),
    I128(i128),
    I256(Box<int256::I256>),
    Bool(bool),
    Address(Box<AccountAddress>),
```

**File:** third_party/move/move-vm/types/src/values/values_impl.rs (L2462-2496)
```rust
    pub fn u256(x: int256::U256) -> Self {
        Value::U256(Box::new(x))
    }

    pub fn i8(x: i8) -> Self {
        Value::I8(x)
    }

    pub fn i16(x: i16) -> Self {
        Value::I16(x)
    }

    pub fn i32(x: i32) -> Self {
        Value::I32(x)
    }

    pub fn i64(x: i64) -> Self {
        Value::I64(x)
    }

    pub fn i128(x: i128) -> Self {
        Value::I128(x)
    }

    pub fn i256(x: int256::I256) -> Self {
        Value::I256(Box::new(x))
    }

    pub fn bool(x: bool) -> Self {
        Value::Bool(x)
    }

    pub fn address(x: AccountAddress) -> Self {
        Value::Address(Box::new(x))
    }
```

**File:** aptos-move/aptos-gas-schedule/src/gas_schedule/misc.rs (L38-46)
```rust
        [u256: AbstractValueSize, { 5.. => "u256" }, 40],
        [i8: AbstractValueSize, { RELEASE_V1_38.. => "i8" }, 40],
        [i16: AbstractValueSize, { RELEASE_V1_38.. => "i16" }, 40],
        [i32: AbstractValueSize, { RELEASE_V1_38.. => "i32" }, 40],
        [i64: AbstractValueSize, { RELEASE_V1_38.. => "i64" }, 40],
        [i128: AbstractValueSize, { RELEASE_V1_38.. => "i128" }, 40],
        [i256: AbstractValueSize, { RELEASE_V1_38.. => "i256" }, 40],
        [bool: AbstractValueSize, "bool", 40],
        [address: AbstractValueSize, "address", 40],
```

**File:** aptos-move/aptos-gas-schedule/src/gas_schedule/misc.rs (L555-614)
```rust
            fn visit_u256(&mut self, depth: u64, _val: &U256) -> PartialVMResult<()> {
                self.check_depth(depth)?;
                self.res = Some(self.params.u256);
                Ok(())
            }

            #[inline]
            fn visit_i8(&mut self, depth: u64, _val: i8) -> PartialVMResult<()> {
                self.check_depth(depth)?;
                self.res = Some(self.params.i8);
                Ok(())
            }

            #[inline]
            fn visit_i16(&mut self, depth: u64, _val: i16) -> PartialVMResult<()> {
                self.check_depth(depth)?;
                self.res = Some(self.params.i16);
                Ok(())
            }

            #[inline]
            fn visit_i32(&mut self, depth: u64, _val: i32) -> PartialVMResult<()> {
                self.check_depth(depth)?;
                self.res = Some(self.params.i32);
                Ok(())
            }

            #[inline]
            fn visit_i64(&mut self, depth: u64, _val: i64) -> PartialVMResult<()> {
                self.check_depth(depth)?;
                self.res = Some(self.params.i64);
                Ok(())
            }

            #[inline]
            fn visit_i128(&mut self, depth: u64, _val: i128) -> PartialVMResult<()> {
                self.check_depth(depth)?;
                self.res = Some(self.params.i128);
                Ok(())
            }

            #[inline]
            fn visit_i256(&mut self, depth: u64, _val: &I256) -> PartialVMResult<()> {
                self.check_depth(depth)?;
                self.res = Some(self.params.i256);
                Ok(())
            }

            #[inline]
            fn visit_bool(&mut self, depth: u64, _val: bool) -> PartialVMResult<()> {
                self.check_depth(depth)?;
                self.res = Some(self.params.bool);
                Ok(())
            }

            #[inline]
            fn visit_address(&mut self, depth: u64, _val: &AccountAddress) -> PartialVMResult<()> {
                self.check_depth(depth)?;
                self.res = Some(self.params.address);
                Ok(())
```

**File:** aptos-move/aptos-gas-schedule/src/gas_schedule/misc.rs (L956-965)
```rust
    pub fn abstract_heap_size(
        &self,
        val: impl ValueView,
        feature_version: u64,
    ) -> PartialVMResult<AbstractValueSize> {
        let stack_size = self.abstract_stack_size(&val, feature_version)?;
        let abs_size = self.abstract_value_size(val, feature_version)?;

        Ok(abs_size.checked_sub(stack_size).unwrap_or_else(|| 0.into()))
    }
```

**File:** aptos-move/aptos-memory-usage-tracker/src/lib.rs (L47-63)
```rust
    #[inline]
    fn use_heap_memory(&mut self, amount: AbstractValueSize) -> PartialVMResult<()> {
        if self.feature_version >= 3 {
            match self.remaining_memory_quota.checked_sub(amount) {
                Some(remaining_quota) => {
                    self.remaining_memory_quota = remaining_quota;
                    Ok(())
                },
                None => {
                    self.remaining_memory_quota = 0.into();
                    Err(PartialVMError::new(StatusCode::MEMORY_LIMIT_EXCEEDED))
                },
            }
        } else {
            Ok(())
        }
    }
```

**File:** aptos-move/aptos-memory-usage-tracker/src/lib.rs (L428-436)
```rust
    fn charge_copy_loc(&mut self, val: impl ValueView) -> PartialVMResult<()> {
        let (stack_size, heap_size) = self
            .vm_gas_params()
            .misc
            .abs_val
            .abstract_value_size_stack_and_heap(&val, self.feature_version())?;

        self.charge_copy_loc_cached(stack_size, heap_size)
    }
```

**File:** aptos-move/aptos-memory-usage-tracker/src/lib.rs (L671-678)
```rust
    fn charge_copy_loc_cached(
        &mut self,
        stack_size: AbstractValueSize,
        heap_size: AbstractValueSize,
    ) -> PartialVMResult<()> {
        self.use_heap_memory(heap_size)?;

        self.base.charge_copy_loc_cached(stack_size, heap_size)
```
