# Audit Report

## Title
Gas Metering Bypass in BCS Native Functions: Deep Copy Operations Executed Before Proportional Gas Charges

## Summary
The `bcs::serialized_size()` and `bcs::to_bytes()` native functions perform expensive deep copy operations via `reference.read_ref()` before charging gas proportional to the data size. This allows attackers to force validators to perform computational work that is significantly undercharged upfront, enabling denial-of-service attacks against validator nodes.

## Finding Description
The `serialized_size_impl()` function performs a deep copy of the referenced value before charging proportional gas. [1](#0-0) 

The gas charging sequence is:
1. Only a base cost of 735 gas units is charged upfront [2](#0-1) 
2. The `reference.read_ref()` call performs a full recursive deep copy of the entire value structure [3](#0-2) 
3. Only AFTER the deep copy completes is per-byte gas charged [4](#0-3) 

The deep copy operation recursively iterates through all nested values and creates new allocations. [5](#0-4)  For vectors, this means copying all elements. [6](#0-5) 

Critically, the `Reference::read_ref()` method does not take a gas meter parameter and performs no gas charging internally. [7](#0-6)  While the VM bytecode instruction `ReadRef` charges gas proportional to value size, native functions calling `reference.read_ref()` directly bypass this mechanism.

The same issue exists in `native_to_bytes()` which also performs the deep copy before any proportional gas charging. [8](#0-7) 

**Attack Scenario:**
1. Attacker creates a resource containing a large vector (e.g., 100,000 u64 values)
2. Attacker calls `bcs::serialized_size()` on this resource repeatedly
3. Each call performs a deep copy of all 100,000 elements with only 735 gas charged upfront
4. Validator CPUs waste cycles on these deep copies
5. Even if full gas is eventually charged, the computational work is frontloaded, allowing parallel exploitation

This violates **Invariant #9** (Resource Limits: "All operations must respect gas, storage, and computational limits") and **Invariant #3** (Move VM Safety: "Bytecode execution must respect gas limits and memory constraints").

## Impact Explanation
This is a **Medium severity** vulnerability per the Aptos bug bounty program. It enables:

- **Validator node slowdowns**: Attackers can force validators to perform expensive operations (deep copying large data structures) for minimal upfront gas cost
- **DoS attack vector**: By submitting many such transactions in parallel, attackers can cause CPU spikes on validators during block execution
- **Gas metering bypass**: Computational work proportional to object size is performed before being charged, violating the principle that expensive operations should be paid for upfront

This does not cause:
- Consensus violations (all validators execute identically)
- Fund loss or theft
- Network partition or liveness failures

The gas schedule defines the base cost as 735 units and per-byte cost as 36 units. [9](#0-8)  For a 100KB serialized object, the upfront charge is only 735 gas while the deep copy work is proportional to the full object size.

## Likelihood Explanation
This vulnerability is **highly likely** to be exploited:

- **Low barrier to entry**: Any user can create resources with large vectors and call BCS functions
- **No special privileges required**: Standard user accounts can execute this attack
- **Easy to automate**: Attackers can submit many such transactions programmatically
- **Already documented**: The TODO comment at line 159 acknowledges that "Reading the reference performs a deep copy, and we can implement it in a more efficient way" [10](#0-9) , though it's framed as a performance optimization rather than a security issue

The same TODO appears in `native_to_bytes()`. [11](#0-10) 

## Recommendation
Charge gas proportional to the value size BEFORE performing the deep copy:

```rust
fn serialized_size_impl(
    context: &mut SafeNativeContext,
    reference: Reference,
    ty: &Type,
) -> PartialVMResult<usize> {
    let ty_layout = context.type_to_type_layout(ty)?;
    
    // Calculate abstract value size BEFORE copying
    let (stack_size, heap_size) = context
        .vm_gas_params()
        .misc
        .abs_val
        .abstract_value_size_stack_and_heap(&reference, context.feature_version())?;
    
    // Charge gas for the deep copy proportional to size
    context.charge(BCS_SERIALIZED_SIZE_PER_COPY_UNIT * (stack_size + heap_size))?;
    
    // Now perform the deep copy
    let value = reference.read_ref()?;
    
    // Calculate and return serialized size
    let function_value_extension = context.function_value_extension();
    let max_value_nest_depth = context.max_value_nest_depth();
    ValueSerDeContext::new(max_value_nest_depth)
        .with_legacy_signer()
        .with_func_args_deserialization(&function_value_extension)
        .with_delayed_fields_serde()
        .serialized_size(&value, &ty_layout)
}
```

Apply the same fix to `native_to_bytes()`. Introduce a new gas parameter `BCS_SERIALIZED_SIZE_PER_COPY_UNIT` or reuse the existing `READ_REF_PER_ABS_VAL_UNIT` parameter for consistency with VM operations.

## Proof of Concept
```move
module attacker::gas_bypass {
    use std::bcs;
    use std::vector;
    use std::signer;
    
    struct LargeData has key, copy, drop {
        data: vector<u64>
    }
    
    /// Setup: Create a resource with a large vector (one-time cost)
    public entry fun setup(account: &signer) {
        let data = vector::empty<u64>();
        let i = 0;
        // Create 100,000 elements
        while (i < 100000) {
            vector::push_back(&mut data, i);
            i = i + 1;
        };
        move_to(account, LargeData { data });
    }
    
    /// Exploit: Call serialized_size repeatedly
    /// Each call performs deep copy of 100,000 elements
    /// but only charges 735 gas upfront
    public entry fun exploit(addr: address) acquires LargeData {
        let large_data = borrow_global<LargeData>(addr);
        
        // Deep copy of 100,000 u64 values happens here
        // Only 735 gas charged before the copy!
        let _size = bcs::serialized_size(large_data);
        
        // Can repeat to amplify attack
        let _size2 = bcs::serialized_size(large_data);
        let _size3 = bcs::serialized_size(large_data);
    }
}
```

**Expected behavior**: Each `bcs::serialized_size()` call performs a deep copy of 100,000 u64 values with only 735 gas charged upfront. The per-byte charge (36 * ~800KB = ~28.8M gas) is only charged after the deep copy completes. By calling this repeatedly or from multiple transactions, validators waste significant CPU cycles on deep copies that are heavily undercharged upfront.

## Notes
The vulnerability affects both `bcs::serialized_size()` and `bcs::to_bytes()` native functions. While the TODO comments acknowledge the deep copy inefficiency, they frame it as a performance optimization opportunity rather than a security issue that violates gas metering invariants.

### Citations

**File:** aptos-move/framework/move-stdlib/src/natives/bcs.rs (L91-93)
```rust
    // TODO(#14175): Reading the reference performs a deep copy, and we can
    //               implement it in a more efficient way.
    let val = ref_to_val.read_ref()?;
```

**File:** aptos-move/framework/move-stdlib/src/natives/bcs.rs (L133-133)
```rust
    context.charge(BCS_SERIALIZED_SIZE_BASE)?;
```

**File:** aptos-move/framework/move-stdlib/src/natives/bcs.rs (L149-149)
```rust
    context.charge(BCS_SERIALIZED_SIZE_PER_BYTE_SERIALIZED * NumBytes::new(serialized_size))?;
```

**File:** aptos-move/framework/move-stdlib/src/natives/bcs.rs (L154-171)
```rust
fn serialized_size_impl(
    context: &mut SafeNativeContext,
    reference: Reference,
    ty: &Type,
) -> PartialVMResult<usize> {
    // TODO(#14175): Reading the reference performs a deep copy, and we can
    //               implement it in a more efficient way.
    let value = reference.read_ref()?;
    let ty_layout = context.type_to_type_layout(ty)?;

    let function_value_extension = context.function_value_extension();
    let max_value_nest_depth = context.max_value_nest_depth();
    ValueSerDeContext::new(max_value_nest_depth)
        .with_legacy_signer()
        .with_func_args_deserialization(&function_value_extension)
        .with_delayed_fields_serde()
        .serialized_size(&value, &ty_layout)
}
```

**File:** third_party/move/move-vm/types/src/values/values_impl.rs (L628-669)
```rust
impl Container {
    fn copy_value(&self, depth: u64, max_depth: Option<u64>) -> PartialVMResult<Self> {
        fn copy_rc_ref_vec_val(
            r: &Rc<RefCell<Vec<Value>>>,
            depth: u64,
            max_depth: Option<u64>,
        ) -> PartialVMResult<Rc<RefCell<Vec<Value>>>> {
            let vals = r.borrow();
            let mut copied_vals = Vec::with_capacity(vals.len());
            for val in vals.iter() {
                copied_vals.push(val.copy_value(depth + 1, max_depth)?);
            }
            Ok(Rc::new(RefCell::new(copied_vals)))
        }

        Ok(match self {
            Self::Vec(r) => Self::Vec(copy_rc_ref_vec_val(r, depth, max_depth)?),
            Self::Struct(r) => Self::Struct(copy_rc_ref_vec_val(r, depth, max_depth)?),

            Self::VecU8(r) => Self::VecU8(Rc::new(RefCell::new(r.borrow().clone()))),
            Self::VecU16(r) => Self::VecU16(Rc::new(RefCell::new(r.borrow().clone()))),
            Self::VecU32(r) => Self::VecU32(Rc::new(RefCell::new(r.borrow().clone()))),
            Self::VecU64(r) => Self::VecU64(Rc::new(RefCell::new(r.borrow().clone()))),
            Self::VecU128(r) => Self::VecU128(Rc::new(RefCell::new(r.borrow().clone()))),
            Self::VecU256(r) => Self::VecU256(Rc::new(RefCell::new(r.borrow().clone()))),
            Self::VecI8(r) => Self::VecI8(Rc::new(RefCell::new(r.borrow().clone()))),
            Self::VecI16(r) => Self::VecI16(Rc::new(RefCell::new(r.borrow().clone()))),
            Self::VecI32(r) => Self::VecI32(Rc::new(RefCell::new(r.borrow().clone()))),
            Self::VecI64(r) => Self::VecI64(Rc::new(RefCell::new(r.borrow().clone()))),
            Self::VecI128(r) => Self::VecI128(Rc::new(RefCell::new(r.borrow().clone()))),
            Self::VecI256(r) => Self::VecI256(Rc::new(RefCell::new(r.borrow().clone()))),
            Self::VecBool(r) => Self::VecBool(Rc::new(RefCell::new(r.borrow().clone()))),
            Self::VecAddress(r) => Self::VecAddress(Rc::new(RefCell::new(r.borrow().clone()))),

            Self::Locals(_) => {
                return Err(
                    PartialVMError::new(StatusCode::UNKNOWN_INVARIANT_VIOLATION_ERROR)
                        .with_message("cannot copy a Locals container".to_string()),
                )
            },
        })
    }
```

**File:** third_party/move/move-vm/types/src/values/values_impl.rs (L1612-1622)
```rust
impl Reference {
    #[cfg_attr(feature = "force-inline", inline(always))]
    pub fn read_ref(self) -> PartialVMResult<Value> {
        self.0.read_ref(1, Some(DEFAULT_MAX_VM_VALUE_NESTED_DEPTH))
    }

    #[cfg(test)]
    pub fn read_ref_with_depth(self, max_depth: u64) -> PartialVMResult<Value> {
        self.0.read_ref(1, Some(max_depth))
    }
}
```

**File:** aptos-move/aptos-gas-schedule/src/gas_schedule/move_stdlib.rs (L42-43)
```rust
        [bcs_serialized_size_base: InternalGas, { RELEASE_V1_18.. => "bcs.serialized_size.base" }, 735],
        [bcs_serialized_size_per_byte_serialized: InternalGasPerByte, { RELEASE_V1_18.. => "bcs.serialized_size.per_byte_serialized" }, 36],
```
